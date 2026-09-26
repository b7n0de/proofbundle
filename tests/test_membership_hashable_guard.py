"""No unguarded membership test on attacker data (deep gate iteration 8, L3-01..L3-04).

THE CLASS, stated as the violated assumption: *a value taken from parsed JSON is hashable.* It is
not. `set` / `dict` / `frozenset` membership HASHES the left operand, so

    if predicate.get("status") not in _OUTCOME_STATUS:   # a set

raises a bare ``TypeError: unhashable type: 'list'`` on ``{"status": []}`` — before any signature is
checked, out of a function whose contract is "returns a verdict or raises ProofBundleError".
Iteration 8 confirmed it on four surfaces including the flagship ``verify_bundle``.

WHY A SCANNER AND NOT 27 REVIEWED DIFFS. The 27 sites are fixed; the scanner is what stops the 28th.
This repository has paid for the instance fix three times already (statuslist.py:122, kbjwt.py:151,
kbjwt.py:230) — each time the outer argument was hardened and an inner field kept crashing. A diff
review cannot see a site that does not exist yet.

THE CONTAINER TYPE IS MEASURED FROM THE AST, NOT LISTED. That is the load-bearing decision, and it
is what covers the 25 `tuple`/`list` neighbours WITHOUT touching them today: they do not hash, so
they are not violations now — but the day someone changes ``_ALLOWED = ("a", "b")`` to
``_ALLOWED = {"a", "b"}`` for speed, every membership test against it becomes a violation and this
scanner turns red in the same commit. A hand-maintained list of "dangerous containers" would have to
be updated by exactly the person who forgot.

HONEST LIMIT: this scans `src/proofbundle/**`, module-level container constants (also when another
module of the package imports them by name, `from .x import NAME`), and single-operator
comparisons. A container built at runtime, reached as a module attribute (`x.NAME`), or a chained
comparison is NOT covered — that is stated here rather than left for someone to discover, and `is_member` is safe
to use everywhere regardless. A LOOKUP or a WRITE hashes its key too (`CONST.get(x)`, `CONST[x]`,
`CONST[x] = v`, `del CONST[x]`, `CONST.setdefault(x)`, `CONST.pop(x)`, and `add`, `discard`,
`remove` on a set); those sites are listed one by one with the reason each is safe, in
`_LOOKUPS_CLASSIFIED` below.
"""
from __future__ import annotations

import ast
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"

_HASHING = {"set", "dict", "frozenset"}


def _hashing_containers(tree: ast.Module) -> dict[str, str]:
    """Module-level names bound to a hash-based container — the ones whose membership test hashes."""
    gefunden: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        ziele = node.targets if isinstance(node, ast.Assign) else [node.target]
        wert = node.value
        if wert is None:
            continue
        art = None
        if isinstance(wert, (ast.Set, ast.SetComp)):
            art = "set"
        elif isinstance(wert, (ast.Dict, ast.DictComp)):
            art = "dict"
        elif (isinstance(wert, ast.Call) and isinstance(wert.func, ast.Name)
                and wert.func.id in ("set", "frozenset", "dict")):
            art = wert.func.id
        if art in _HASHING:
            for t in ziele:
                if isinstance(t, ast.Name):
                    gefunden[t.id] = art
    return gefunden


def _modulname(pfad: Path, wurzel: Path) -> str:
    return pfad.relative_to(wurzel).with_suffix("").as_posix().replace("/", ".").removesuffix(".__init__")


def containers_by_module(quellen: dict[str, str]) -> dict[str, dict[str, str]]:
    """module -> {name: art} for the module-level hashing containers of every module given."""
    return {modul: _hashing_containers(ast.parse(text)) for modul, text in quellen.items()}


def _package_sources() -> dict[str, tuple[str, bool]]:
    """module -> (source, is_package_init) for every module under src/proofbundle."""
    return {_modulname(p, SRC.parent): (p.read_text(encoding="utf-8"), p.name == "__init__.py")
            for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts}


def imported_containers(tree: ast.Module, modul: str, ist_init: bool,
                        je_modul: dict[str, dict[str, str]]) -> dict[str, str]:
    """Names this module binds by `from <module> import NAME [as ALIAS]` to a hashing container that
    module defines. Gate run 1 on 11110281 (234-1-02): `_hashing_containers` read one file, so a dict
    imported from another module was no container at all; `renewal.py` read `HASH_REGISTRY` from
    `hashalg`, `cli.py` read `AUTOMATION_BLOCKER_REASONS` from `bundle`, and `relation_statement.py`
    tested membership in `SUCCESSOR_RELATIONS` from `relation`, all four unseen. An import inside a
    function counts for the whole file: that reads more, never less."""
    paket = modul if ist_init else modul.rpartition(".")[0]
    gefunden: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            basis = paket
            for _ in range(node.level - 1):
                basis = basis.rpartition(".")[0]
            ziel = f"{basis}.{node.module}" if node.module else basis
        else:
            ziel = node.module or ""
        for alias in node.names:
            art = je_modul.get(ziel, {}).get(alias.name)
            if art:
                gefunden[alias.asname or alias.name] = art
    return gefunden


def _behaelter(tree: ast.Module, modul: str | None, ist_init: bool = False,
               je_modul: dict[str, dict[str, str]] | None = None) -> dict[str, str]:
    """The hashing containers a module can see: its own, and with `modul` the ones it imports."""
    eigene = _hashing_containers(tree)
    if modul is None or je_modul is None:
        return eigene
    return {**imported_containers(tree, modul, ist_init, je_modul), **eigene}


def unguarded_membership_sites(quelle: str, name: str = "<quelle>", modul: str | None = None,
                               ist_init: bool = False,
                               je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(Zeile, linker Ausdruck, Behälter) für jeden ungeschützten Mitgliedstest.

    A CONSTANT left operand is skipped on purpose: ``"status" in predicate`` asks whether a KEY is
    present, the left side is a literal string, and a literal is always hashable. Flagging it would
    make the scanner noisy exactly where it is always right, and a noisy scanner gets silenced."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _behaelter(tree, modul, ist_init, je_modul)
    treffer: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            continue
        rechts = node.comparators[0]
        if not isinstance(rechts, ast.Name) or rechts.id not in behaelter:
            continue
        if isinstance(node.left, ast.Constant):
            continue
        treffer.append((node.lineno, ast.unparse(node.left), rechts.id))
    return treffer


def _liest_aus_geparsten_daten(knoten: ast.AST) -> bool:
    """Heuristik, und sie wird hier als solche benannt: kommt dieser Ausdruck aus geparsten Daten?

    Gemessen wird ausschliesslich der ``.get(...)``-Aufruf, also genau das Idiom, mit dem dieses
    Repository geparstes JSON liest.

    WARUM NICHT AUCH DER INDEX ``x["k"]``, gemessen beim Bauen am 14.09.2026: die erste Fassung
    zaehlte ihn mit und meldete sofort ``relation_statement.py:340``,
    ``sorted({v["code"] for v in _viol})``. Das ist ein FEHLALARM — ``_viol`` wird sieben Zeilen
    darueber im Haus selbst gebaut, mit den Literalen ``"code"`` und ``"message"``. Der Index sagt
    nichts ueber die HERKUNFT des Werts, und ein Riegel, der bei hauseigenen Daten schreit, wird
    abgeschaltet; genau davor warnt der Kommentar zu ``_ERSATZ_STAEMME`` in diesem Haus seit Wochen.

    EHRLICHE UNTERGRENZE, als Vertrag festgehalten statt als Fussnote: ein Index auf wirklich
    fremde Daten (``doc["x"]``) entgeht diesem Detektor, und wer den Wert vorher in eine Variable
    legt, ebenfalls. Wer das schaerfen will, braucht eine Herkunftsverfolgung (ist die Basis ein
    Parameter oder aus einem Parameter abgeleitet?) — das ist eine eigene Arbeit und keine
    Nebenbei-Verschaerfung.
    """
    for k in ast.walk(knoten):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr == "get"):
            return True
    return False


def _durch_isinstance_gedeckt(ausdruck: ast.AST, generatoren: list) -> bool:
    """Steht in den ``if``-Klauseln der Comprehension ein ``isinstance`` GENAU auf diesen Ausdruck?"""
    ziel = ast.unparse(ausdruck)
    for g in generatoren:
        for bed in g.ifs:
            for k in ast.walk(bed):
                if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                        and k.func.id == "isinstance" and k.args
                        and ast.unparse(k.args[0]) == ziel):
                    return True
    return False


def unguarded_hashing_constructions(quelle: str, name: str = "<quelle>") -> list[tuple[int, str]]:
    """(Zeile, gehashter Ausdruck) je Stelle, die beim AUFBAU eines Hash-Behaelters ungepruefte
    Daten hasht.

    WARUM ES DIESEN ZWEITEN DETEKTOR GIBT, gemessen am 14.09.2026. ``unguarded_membership_sites``
    besucht ausschliesslich ``ast.Compare`` mit ``in``/``not in`` und verlangt ausserdem, dass der
    Behaelter ein MODULWEITER Name ist. Beide Bedingungen verfehlten dieselbe echte Stelle:

        zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}   # cap1.py:220

    Der Behaelter entsteht LOKAL, und gehasht wird nicht im Test, sondern schon in der
    Comprehension — ein unhashbarer ``stratum``-Wert loeste dort ein rohes ``TypeError`` aus. Gegen
    den vollen Quelltext von ``cap1.py`` lieferte der alte Scanner NULL Treffer, waehrend der
    Defekt ausfuehrbar reproduzierbar war. Ein Scanner, der eine Klasse nur in EINER ihrer Formen
    kennt, meldet gruen und meint "diese Form kommt nicht vor".

    Der Modulkopf von ``_membership.py`` sagt "with a scanner that fails on any new unguarded
    site". Dieser Detektor ist der Teil dieser Zusage, der gefehlt hat.
    """
    tree = ast.parse(quelle, filename=name)
    treffer: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.SetComp):
            gehasht, gen = node.elt, node.generators
        elif isinstance(node, ast.DictComp):
            gehasht, gen = node.key, node.generators
        else:
            continue
        if isinstance(gehasht, ast.Constant):
            continue
        if not _liest_aus_geparsten_daten(gehasht):
            continue
        if _durch_isinstance_gedeckt(gehasht, gen):
            continue
        treffer.append((node.lineno, ast.unparse(gehasht)))
    return treffer


def _grundlinie() -> dict:
    import json  # noqa: PLC0415
    return json.loads((REPO / "conformance" / "unguarded_hashing_constructions_baseline.json")
                      .read_text(encoding="utf-8"))


def _umschliessende_definition(quelle: str) -> dict[int, str]:
    """Zeile -> qualifizierter Name der umschliessenden def/class, sonst '<modulebene>'.

    WARUM DIESER SCHLUESSELTEIL EXISTIERT, gemessen am 15.09.2026 von einer adversarialen Linse.
    Eine Fassung dieses Riegels band auf (Datei, Ausdruck) mit Anzahl. Damit liess sich das Budget
    WASCHEN: die getragene, angreiferexponierte Stelle in ``derive_limitation_codes`` schliessen und
    anderswo in derselben Datei eine NEUE ungeschuetzte Konstruktion mit DEMSELBEN Ausdruck
    aufmachen — die Anzahl blieb drei, der Riegel blieb gruen, und der neue Code warf nachweislich
    ``TypeError: unhashable type: 'list'``. Die alte, zeilengebundene Regel HAETTE ihn gefangen.
    Der Name der umschliessenden Definition ueberlebt eine Zeilenverschiebung und unterscheidet
    trotzdem zwei Stellen: eine neue Stelle landet in einer anderen Definition und ist damit neu.
    """
    baum = ast.parse(quelle)
    karte: dict[int, str] = {}

    def geh(knoten: ast.AST, praefix: str) -> None:
        for k in ast.iter_child_nodes(knoten):
            if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{praefix}.{k.name}" if praefix else k.name
                for tief in ast.walk(k):
                    if hasattr(tief, "lineno"):
                        karte.setdefault(tief.lineno, name)
                geh(k, name)
            else:
                geh(k, praefix)

    geh(baum, "")
    return karte


def _gesehene_stellen(quelltexte: dict[str, str] | None = None) -> dict[tuple[str, str, str], list[int]]:
    """(Datei, umschliessende Definition, Ausdruck) -> Zeilen.

    Die Zeilen werden MITGEFUEHRT, damit eine Meldung einen Menschen hinschickt — aber sie sind
    NICHT der Schluessel. Wer sie zum Schluessel macht, baut ein Tor, das jeder Merge neu scharf
    stellt, ohne dass sich eine einzige Stelle geaendert haette.

    EIN LEERES quelltexte IST EIN FEHLER, kein leerer Baum (Linsenfund P3 vom 15.09.2026): die
    Pruefung lautete ``is not None``, und ein leeres dict uebersprang damit still den GANZEN
    Plattenlauf und meldete sauber. Ein kuenftiger Aufrufer, der nur geaenderte Dateien reicht,
    waere genau so in ein stilles Gruen gelaufen.
    """
    if quelltexte is not None and not quelltexte:
        raise ValueError(
            "leeres quelltexte: das waere ein stiller Freispruch ueber einen ungeprueften Baum. "
            "Fuer den vollen Baum None uebergeben, nicht {}")
    gesehen: dict[tuple[str, str, str], list[int]] = {}
    paare = (quelltexte.items() if quelltexte is not None
             else ((str(d.relative_to(SRC.parent)), d.read_text(encoding="utf-8"))
                   for d in sorted(SRC.rglob("*.py"))))
    for name, quelle in paare:
        wo = _umschliessende_definition(quelle)
        for zeile, ausdruck in unguarded_hashing_constructions(quelle, name):
            gesehen.setdefault((name, wo.get(zeile, "<modulebene>"), ausdruck), []).append(zeile)
    return gesehen


def _ueberzaehlige_stellen(quelltexte: dict[str, str] | None = None) -> list[str]:
    """Was die Grundlinie NICHT deckt — je (Datei, Ausdruck) die Anzahl ueber dem getragenen Stand."""
    import collections  # noqa: PLC0415
    getragen = collections.Counter(
        (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
    funde: list[str] = []
    for schluessel, zeilen in sorted(_gesehene_stellen(quelltexte).items()):
        ueberzaehlig = len(zeilen) - getragen.get(schluessel, 0)
        if ueberzaehlig > 0:
            funde.append(f"{schluessel[0]}  in {schluessel[1]}()  {schluessel[2]}  "
                         f"{ueberzaehlig} von {len(zeilen)} nicht getragen, Zeilen {sorted(zeilen)}")
    return funde


#: The methods that hash their first argument, per kind of module-level container. A lens on 3c513874
#: (the 228bc stack delta, D-2) wrote `_VERIFIERS[type_name] = verifier` and `_VERIFIERS.setdefault(...)`
#: past the first form, which knew `.get` and a read `CONST[x]` only: a write hashes its key as a read
#: does. `update` and `fromkeys` take a whole mapping or iterable and are a named limit.
_HASHING_METHODS = {"dict": {"get", "setdefault", "pop"}, "set": {"add", "discard", "remove"},
                    "frozenset": set()}


def constant_lookups(quelle: str, name: str = "<quelle>", modul: str | None = None,
                     ist_init: bool = False,
                     je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(line, container, key) for every call of a method that hashes its argument on a module-level
    hashing container CONST (`get`, `setdefault`, `pop` on a dict; `add`, `discard`, `remove` on a set),
    and every `CONST[x]` on a dict whether it reads, writes or deletes, where CONST is the module's own or
    with `modul` one it imports from the package, and the key is not a literal. Such an access hashes `x`
    and raises TypeError for an unhashable one."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _behaelter(tree, modul, ist_init, je_modul)
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id in behaelter
                and node.func.attr in _HASHING_METHODS[behaelter[node.func.value.id]] and node.args):
            key, const = node.args[0], node.func.value.id
        elif (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
              and behaelter.get(node.value.id) == "dict"):
            key, const = node.slice, node.value.id
        else:
            continue
        if not isinstance(key, ast.Constant):
            found.append((node.lineno, const, ast.unparse(key)))
    return found


#: Every lookup on a module-level dict with a key that is not a literal, and why it cannot raise.
#: Keyed by (file, enclosing definition, dict, key), not by line (the lesson of the baseline below).
#: WHERE THIS COMES FROM: the ECMA-reading generator of the 228bc fix sent a list as a trust pack key's
#: `alg`, and `_KEY_ALG_LABEL.get(alg)` raised TypeError out of `verify_trust_pack` before any signature
#: was counted. The membership scanner above sees `in` and `not in`, not a lookup. Measured on 9151e4ca
#: (2026-09-26): 14 sites, none open. Gate run 1 on 11110281 (234-1-02) found three more that the first
#: form could not see, because their dict is imported from another module: 17 then. The 228bc stack
#: delta (D-2) found the writes, `CONST[x] = v` and `.setdefault`, which the lookup form did not visit:
#: 19 now, none open. A new site turns this red until it is classified here; a site that is gone must
#: leave the list.
_LOOKUPS_CLASSIFIED = {
    ("proofbundle/__init__.py", "__getattr__", "_LAZY", "name"):
        "own value: the attribute protocol passes a str",
    ("proofbundle/agent_review.py", "evaluate_time_policy", "_POLICY_ACHSE", "art"):
        "guarded: isinstance(art, str) and is_member(art, _POLICY_ACHSE) return before it",
    ("proofbundle/anchors.py", "verify_anchor", "_VERIFIERS", "atype"):
        "guarded: isinstance(atype, str) and is_member(atype, _VERIFIERS) return before it",
    ("proofbundle/hashalg.py", "resolve_hash_alg", "HASH_REGISTRY", "alg_id"):
        "guarded: a non-str alg_id raises MissingHashAlgId before it",
    ("proofbundle/intoto.py", "to_test_result_statement", "_RESULT_ENUM", "verdikt"):
        "own value: require_bool_verdict returns a bool or raises",
    ("proofbundle/kbjwt.py", "verify_key_binding", "_HASH_ALG", "sd_alg"):
        "guarded: is_member(sd_alg, _HASH_ALG) returns before it",
    ("proofbundle/policy_profiles.py", "canonical_profile_name", "PROFILE_ALIASES", "short"):
        "guarded: is_member(short, PROFILE_ALIASES) in the same branch",
    ("proofbundle/policy_profiles.py", "profile_path", "PROFILE_ALIASES", "short"):
        "guarded: is_member(short, PROFILE_ALIASES) in the same branch",
    ("proofbundle/policy_profiles.py", "profile_path", "PROFILE_NAMES", "canonical"):
        "guarded: canonical is a member of PROFILE_NAMES or a value of PROFILE_ALIASES, else it raised",
    ("proofbundle/sdjwt.py", "_digest", "_HASH_ALG", "alg"):
        "guarded by the one caller: verify_sd_jwt returns on not is_member(sd_alg, _HASH_ALG) first",
    ("proofbundle/sdjwt.py", "verify_sd_jwt", "_ISSUER_SIG_VERIFIERS", "alg"):
        "guarded: isinstance(alg, str) in the same expression",
    ("proofbundle/sdjwt_issue.py", "present_with_key_binding", "_HASH_BY_SD_ALG", "sd_alg"):
        "guarded: is_member(sd_alg, _HASH_BY_SD_ALG) raises ValueError before it",
    ("proofbundle/statuslist.py", "verify_status_snapshot", "STATUS_LABELS", "status"):
        "own value: an int read from the bit array",
    ("proofbundle/trust_pack.py", "validate_trust_pack_predicate", "_KEY_ALG_LABEL", "alg"):
        "guarded: `alg in _KEY_ALGS` against a tuple, which compares and hashes nothing",
    # Three more, seen once imported containers counted (gate run 1 on 11110281, 234-1-02).
    ("proofbundle/renewal.py", "_is_deprecated_hash", "HASH_REGISTRY", "alg"):
        "guarded: a non-str alg returns False before it",
    ("proofbundle/renewal.py", "verify_sequence", "HASH_REGISTRY", "newest.hash_alg"):
        "guarded: isinstance(newest.hash_alg, str) in the same expression",
    ("proofbundle/cli.py", "_cmd_verify", "AUTOMATION_BLOCKER_REASONS", "_blk"):
        "own value: bundle.py builds automationBlockers from string literals only",
    # Two writes, seen once a write hashes its key as a read does (the 228bc stack delta, D-2).
    ("proofbundle/anchors.py", "register_anchor_type", "_VERIFIERS", "type_name"):
        "guarded: a type_name that is no non-empty str raises BundleFormatError before it",
    ("proofbundle/anchors.py", "_ensure_builtin_types", "_VERIFIERS", "anchors_chia.ANCHOR_TYPE"):
        "own value: anchors_chia.ANCHOR_TYPE is the string literal \"chia-datalayer/v1\"",
}


def _constant_lookups_in_tree() -> set:
    quellen = _package_sources()
    je_modul = containers_by_module({m: q for m, (q, _i) in quellen.items()})
    seen = set()
    for d in sorted(SRC.rglob("*.py")):
        if "__pycache__" in d.parts:
            continue
        modul = _modulname(d, SRC.parent)
        quelle, ist_init = quellen[modul]
        wo = _umschliessende_definition(quelle)
        for zeile, const, key in constant_lookups(quelle, str(d), modul, ist_init, je_modul):
            seen.add((str(d.relative_to(SRC.parent)), wo.get(zeile, "<modulebene>"), const, key))
    return seen


class TestNoUnguardedMembershipInTheTree(unittest.TestCase):
    def test_no_source_file_hashes_attacker_data_in_a_membership_test(self):
        quellen = _package_sources()
        je_modul = containers_by_module({m: q for m, (q, _i) in quellen.items()})
        befunde = []
        for pfad in sorted(SRC.rglob("*.py")):
            if "__pycache__" in pfad.parts or pfad.name == "_membership.py":
                continue
            modul = _modulname(pfad, SRC.parent)
            for zeile, links, cont in unguarded_membership_sites(
                    quellen[modul][0], str(pfad), modul, quellen[modul][1], je_modul):
                befunde.append(f"{pfad.relative_to(SRC.parent)}:{zeile}  {links} in {cont}")
        self.assertEqual(
            befunde, [],
            "unguarded membership test(s) on a hashing container — route through "
            "proofbundle._membership.is_member:\n  " + "\n  ".join(befunde))

    def test_no_source_file_builds_a_hash_container_from_unchecked_data(self):
        """DER LIVE-GUARD FUER DIE ZWEITE FORM. Er faengt, was der Mitgliedstest-Scanner nicht sieht.

        Gemessen 14.09.2026: `cap1.py:220` baute `{a.get("stratum") for a in aa ...}` aus
        ungeprueften Dokumentwerten. Der aeltere Scanner lieferte gegen dieselbe Datei NULL
        Treffer, weil er nur `in`/`not in` gegen MODULWEITE Behaelter kennt. Der Defekt war
        gleichzeitig ausfuehrbar reproduzierbar. Gruen hiess dort nicht "kommt nicht vor",
        sondern "diese Form wird nicht gemessen".
        """
        funde = _ueberzaehlige_stellen()
        self.assertEqual(funde, [], "\n".join(
            ["ein Hash-Behaelter wird aus ungeprueften Daten gebaut — das hasht beim AUFBAU, "
             "bevor irgendein Mitgliedstest laeuft. Die sieben Bestandsstellen stehen namentlich "
             "in conformance/unguarded_hashing_constructions_baseline.json, gefuehrt als "
             "(Datei, Ausdruck) mit Anzahl; UEBERZAEHLIG ist:"] + funde))

    def test_die_grundlinie_weist_sich_als_luecke_aus_nicht_als_erlaubnis(self):
        """Eine Grundlinie, die sich als Erlaubnis liest, wird zur Erlaubnis.

        Sie muss (a) sagen, WARUM es sie gibt, (b) je Stelle die Exponiertheit benennen oder sie
        ehrlich als NICHT GEMESSEN markieren, und (c) ihre eigene Untergrenze tragen.
        """
        import json
        g = json.loads((REPO / "conformance" / "unguarded_hashing_constructions_baseline.json")
                       .read_text(encoding="utf-8"))
        self.assertIn("NAMED GAP, not permission", g["why_this_file_exists"])
        self.assertTrue(g["honest_limit"], "die Untergrenze fehlt")
        for e in g["carried"]:
            marke = f"{e.get('file')}  {e.get('expr')}"
            self.assertTrue(e.get("file"), f"{e}: kein Feld file")
            self.assertTrue(e.get("expr"), f"{marke}: kein Feld expr — ohne Ausdruck ist der "
                                           "Eintrag nicht zuordenbar, sobald Zeilen wandern")
            self.assertTrue(e.get("qualname"), f"{marke}: kein Feld qualname — ohne die "
                                               "umschliessende Definition laesst sich das Budget "
                                               "waschen (Linsenfund 15.09.2026)")
            self.assertTrue(e.get("exposure"), f"{marke}: keine Aussage zur Exponiertheit")
            if not e.get("exposure_measured"):
                self.assertIn("NICHT GEMESSEN", e["exposure"],
                              f"{marke}: ungemessen, sagt es aber nicht")

    def test_die_grundlinie_ueberlebt_eine_zeilenverschiebung(self):
        """DER FALL, DER AM 15.09.2026 ROT WAR — und der vor dem Klassenfix rot werden KONNTE.

        Gemessen an diesem Tag: der Merge von origin/main in diesen Zweig fuegte
        ``agent_review.py`` 19 Zeilen hinzu. Keine einzige der sieben getragenen Stellen aenderte
        sich, aber alle sieben wanderten — und der Riegel meldete seine EIGENE Grundlinie als
        sieben neue Funde. Die alte Regel verglich ``datei:zeile``; eine Zeilennummer ist eine
        Eigenschaft der umgebenden Datei, nicht der Stelle.

        Dieser Fall haette mit der alten Regel sieben Funde ergeben und ist damit ein echter
        Anti-Fall, kein gruener Zeuge: er kann fallen, sobald jemand wieder an die Zeile bindet.
        """
        verschoben = {str(d.relative_to(SRC.parent)): "\n" * 40 + d.read_text(encoding="utf-8")
                      for d in sorted(SRC.rglob("*.py"))}
        self.assertEqual(
            _ueberzaehlige_stellen(verschoben), [],
            "die Grundlinie haengt wieder an Zeilennummern — jeder Merge stellt das Tor neu scharf, "
            "ohne dass sich eine Stelle geaendert haette")

    def test_eine_vierte_stelle_derselben_form_gilt_als_neu(self):
        """DIE GEGENRICHTUNG ZUR ANZAHL. Ohne sie waere der Klassenfix eine Erlaubnis.

        Der Schluessel ist (Datei, Definition, Ausdruck) — waere die Anzahl nicht dabei, deckte ein
        getragener Eintrag beliebig viele weitere Vorkommen derselben Form in DERSELBEN Definition.
        ``derive_limitation_codes`` traegt genau EIN ``i.get('assurance')``; ein zweites dort ist neu.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    a = {i.get('assurance') for i in xs}\n"
                  "    b = {i.get('assurance') for i in xs}\n"
                  "    return a, b\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(len(funde), 1, funde)
        self.assertIn("1 von 2 nicht getragen", funde[0])

    def test_eine_neue_definition_mit_getragenem_ausdruck_gilt_als_neu(self):
        """DER WASCHGANG, den eine adversariale Linse am 15.09.2026 ausgefuehrt hat.

        Sie schloss die getragene, angreiferexponierte Stelle in ``derive_limitation_codes`` und
        machte anderswo in derselben Datei eine NEUE ungeschuetzte Konstruktion mit DEMSELBEN
        Ausdruck auf. Bei einem Schluessel aus (Datei, Ausdruck) blieb die Anzahl gleich und der
        Riegel gruen — im neuen Code lief nachweislich ``TypeError: unhashable type: 'list'``. Die
        vorherige, zeilengebundene Regel haette ihn gefangen; die Reparatur war also auf DIESER
        Achse schwaecher als das, was sie ersetzte.

        Genau diese Bewegung wird hier nachgestellt: dieselbe Datei, derselbe Ausdruck, dieselbe
        Gesamtzahl — nur eine andere umschliessende Definition. Bleibt dieser Test gruen, ist das
        Budget wieder waschbar.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    return set()\n"
                  "\n"
                  "def _neu_und_ungeprueft(xs):\n"
                  "    return {i.get('assurance') for i in xs}\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(
            len(funde), 1,
            "eine neue Definition mit einem getragenen Ausdruck gilt nicht als neu — das Budget "
            f"laesst sich waschen: {funde}")
        self.assertIn("_neu_und_ungeprueft", funde[0])

    def test_ein_leeres_quelltexte_ist_ein_fehler_kein_sauberer_baum(self):
        """Linsenfund P3: ``is not None`` liess ein leeres dict den ganzen Plattenlauf still
        ueberspringen und sauber melden. Ein Aufrufer, der nur geaenderte Dateien reicht und einmal
        keine hat, haette damit einen ungeprueften Baum freigesprochen."""
        with self.assertRaises(ValueError):
            _ueberzaehlige_stellen({})

    def test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt(self):
        """Eine Grundlinie, die eine geschlossene Stelle weiter traegt, ist eine Erlaubnis auf Vorrat.

        Die Datei sagt von sich: *jeder Eintrag muss noch geschlossen werden*. Wird einer
        geschlossen und der Eintrag bleibt stehen, deckt er ab da eine Stelle, die es nicht mehr
        gibt — und die naechste, die dieselbe Form wieder einfuehrt, faellt lautlos darunter.
        Rot heisst hier: Eintrag entfernen, nicht Test entfernen.
        """
        import collections  # noqa: PLC0415
        getragen = collections.Counter(
            (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
        gesehen = {k: len(v) for k, v in _gesehene_stellen().items()}
        tot = [f"{f}  in {q}()  {x}: getragen {n}, im Baum {gesehen.get((f, q, x), 0)}"
               for (f, q, x), n in sorted(getragen.items()) if gesehen.get((f, q, x), 0) < n]
        self.assertEqual(tot, [], "\n".join(
            ["die Grundlinie traegt Stellen, die im Baum nicht mehr vorkommen — entfernen:"] + tot))

    def test_a_planted_unguarded_construction_is_found(self):
        """PLANT-AND-MUST-CATCH fuer die zweite Form, woertlich die historische Zeile."""
        quelle = ('def r8(doc, aa):\n'
                  '    zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}\n'
                  '    return zitiert\n')
        self.assertEqual(len(unguarded_hashing_constructions(quelle)), 1,
                         "die historische Form muss gefangen werden")

    def test_anti_parity_a_guarded_construction_is_not_flagged(self):
        """DIE GEGENRICHTUNG. Wer den Wert vorher auf str prueft, hasht nichts Unhashbares."""
        quelle = ('def r8(aa):\n'
                  '    z = {a.get("stratum") for a in aa if isinstance(a.get("stratum"), str)}\n'
                  '    return z\n')
        self.assertEqual(unguarded_hashing_constructions(quelle), [])

    def test_anti_parity_a_literal_set_is_not_flagged(self):
        """Ein Mengenliteral hasht nur, was im Quelltext steht — nie fremde Daten."""
        self.assertEqual(unguarded_hashing_constructions('X = {"a", "b"}\n'), [])

    def test_UNTERGRENZE_ein_index_auf_fremde_daten_entgeht_dem_detektor(self):
        """DIE GRENZE ALS VERTRAG, absichtlich GRUEN obwohl der Fall echt waere.

        ``{doc["x"] for doc in docs}`` hasht fremde Daten genauso — der Detektor sieht es nicht,
        weil ein Index nichts ueber die Herkunft sagt und die erste, weitere Fassung dadurch einen
        nachgemessenen Fehlalarm erzeugte (``relation_statement.py:340``, hauseigene Liste).
        Wer diesen Vertrag spaeter ROT bekommt, hat den Detektor um eine Herkunftsverfolgung
        erweitert und darf ihn neu schreiben; wer ihn LOESCHT, weil er unbequem ist, hat die
        Grenze verloren und merkt es nicht mehr.
        """
        quelle = 'def f(docs):\n    return {doc["x"] for doc in docs}\n'
        self.assertEqual(unguarded_hashing_constructions(quelle), [],
                         "die Untergrenze hat sich verschoben — Vertrag neu schreiben, nicht loeschen")

    def test_the_guard_is_actually_imported_where_it_is_used(self):
        # A call to a name that was never imported is a NameError at runtime, i.e. a crash in the
        # very code path meant to prevent one. Cheap to check, expensive to discover in production.
        for pfad in sorted(SRC.rglob("*.py")):
            if "__pycache__" in pfad.parts or pfad.name == "_membership.py":
                continue
            text = pfad.read_text(encoding="utf-8")
            if "is_member(" not in text:
                continue
            with self.subTest(datei=str(pfad.relative_to(SRC.parent))):
                # import-ORDER-robust: `from ._membership import as_dict, is_member` is isort-canonical,
                # so a literal-substring check for "_membership import is_member" false-flags a legitimate
                # multi-name import. The INTENT is unchanged — is_member must be imported from _membership
                # where it is called — and this regex checks exactly that regardless of the name order.
                import re as _re  # noqa: PLC0415
                self.assertTrue(
                    _re.search(r"_membership import [\w,\s]*\bis_member\b", text),
                    f"{pfad.name} calls is_member() but does not import it from _membership")


class TestTheScannerActuallyCatches(unittest.TestCase):
    """Plant-and-must-catch, both directions. Without this the file above proves only that the tree
    is clean OR that the scanner is blind, and those two look identical from the outside."""

    def test_a_planted_unguarded_site_is_found(self):
        gepflanzt = textwrap.dedent('''
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return "status" in p and p.get("status") not in _ALLOWED
        ''')
        treffer = unguarded_membership_sites(gepflanzt)
        self.assertEqual(len(treffer), 1, treffer)
        self.assertEqual(treffer[0][2], "_ALLOWED")

    def test_anti_parity_the_guarded_form_is_not_flagged(self):
        # Without this, a scanner that flags EVERY membership test would pass the test above and
        # then be silenced by the first person who has to look at its output.
        geschuetzt = textwrap.dedent('''
            from ._membership import is_member
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return "status" in p and not is_member(p.get("status"), _ALLOWED)
        ''')
        self.assertEqual(unguarded_membership_sites(geschuetzt), [])

    def test_anti_parity_a_key_presence_test_is_not_flagged(self):
        # `"status" in predicate` is the single most common membership test in this codebase and is
        # never a defect: the left side is a literal, and a literal is always hashable.
        harmlos = textwrap.dedent('''
            _ALLOWED = {"ok"}
            def validate(p):
                return "status" in p and "x" in _ALLOWED
        ''')
        self.assertEqual(unguarded_membership_sites(harmlos), [])

    def test_a_tuple_container_is_not_flagged_today(self):
        # Today's honest state: a tuple does not hash, so this cannot raise.
        mit_tuple = textwrap.dedent('''
            _ALLOWED = ("ok", "fail")
            def validate(p):
                return p.get("status") not in _ALLOWED
        ''')
        self.assertEqual(unguarded_membership_sites(mit_tuple), [])

    def test_the_same_site_IS_flagged_once_that_tuple_becomes_a_set(self):
        # THE POINT OF MEASURING THE CONTAINER TYPE. `statuslist._ALLOWED_BITS` and
        # `policy._SUPPORTED_SCHEMAS` are tuples and therefore only ACCIDENTALLY safe; iteration 8
        # named exactly that. A tuple -> set change for speed silently arms this defect class, and
        # this assertion is what makes that change loud instead of silent.
        als_set = textwrap.dedent('''
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return p.get("status") not in _ALLOWED
        ''')
        self.assertEqual(len(unguarded_membership_sites(als_set)), 1)


class TestEveryConstantLookupOnAForeignKeyIsClassified(unittest.TestCase):
    """The third form of the class: a lookup hashes its key as a membership test does.

    STATED LIMIT: the guard finds every such lookup and holds the list exact; it does NOT prove the
    reasons in `_LOOKUPS_CLASSIFIED`. A person read each guard before classifying the site, and a
    guard removed later leaves the reason standing. Only a test that sends an unhashable value to the
    surface can catch that; this one cannot."""

    def test_the_tree_holds_exactly_the_classified_lookups(self):
        seen = _constant_lookups_in_tree()
        self.assertEqual(sorted(seen - set(_LOOKUPS_CLASSIFIED)), [],
                         "a new lookup on a module-level dict with a foreign key: route the key through "
                         "is_member first, or classify it in _LOOKUPS_CLASSIFIED with the reason")
        self.assertEqual(sorted(set(_LOOKUPS_CLASSIFIED) - seen), [],
                         "a classified lookup is gone: remove it from _LOOKUPS_CLASSIFIED")

    def test_every_classification_says_why(self):
        for key, reason in _LOOKUPS_CLASSIFIED.items():
            with self.subTest(site=key):
                self.assertRegex(reason, r"^(guarded|guarded by the one caller|own value): \S")

    def test_a_planted_lookup_is_found_and_a_literal_key_is_not(self):
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(p):
                return _M.get(p.get("k")), _M[p["k"]], _M["a"], _M.get("a"), p.get("x")
        ''')
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(quelle)],
                         [("_M", "p.get('k')"), ("_M", "p['k']")])

    def test_a_write_hashes_its_key_as_a_read_does(self):
        """The 228bc stack delta (D-2): a write and `.setdefault` were unseen. Every form that hashes a
        foreign key is found, and a literal key is not, in any of them."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(p, k):
                _M[k] = 1
                del _M[k]
                _M.setdefault(k, 2)
                _M.pop(k, None)
                _S.add(k)
                _S.discard(k)
                _S.remove(k)
                _M["a"] = 1
                _M.setdefault("a", 2)
                _S.add("a")
                return _S.get
        ''')
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(quelle)],
                         [("_M", "k")] * 4 + [("_S", "k")] * 3)

    def test_an_imported_container_is_seen_in_both_forms(self):
        """234-1-02 as a planted package: a dict and a frozenset defined in one module, read in another
        through `from .a import ...` (one of them inside a function, as cli.py does)."""
        a = '_M = {"x": 1}\n_S = frozenset({"x"})\n'
        b = ("from .a import _M\n"
             "def f(p):\n"
             "    from .a import _S as S\n"
             "    return _M.get(p.get('k')), p.get('r') in S\n")
        je_modul = containers_by_module({"pkg.a": a, "pkg.b": b})
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(b, "b.py", "pkg.b", False, je_modul)],
                         [("_M", "p.get('k')")])
        self.assertEqual([(links, c) for _l, links, c in
                          unguarded_membership_sites(b, "b.py", "pkg.b", False, je_modul)],
                         [("p.get('r')", "S")])
        # anti-parity: without the package view the same file shows nothing, which was the first form
        self.assertEqual(constant_lookups(b, "b.py"), [])

    def test_a_relative_import_resolves_from_a_subpackage_and_an_init(self):
        je_modul = containers_by_module({"pkg.a": '_M = {"x": 1}\n', "pkg.sub.c": "", "pkg": ""})
        tiefer = "from ..a import _M\ndef f(p):\n    return _M[p]\n"
        self.assertEqual(len(constant_lookups(tiefer, "c.py", "pkg.sub.c", False, je_modul)), 1)
        init = "from .a import _M\ndef f(p):\n    return _M[p]\n"
        self.assertEqual(len(constant_lookups(init, "__init__.py", "pkg", True, je_modul)), 1)

    def test_the_trust_pack_shape_raised_before_it_was_guarded(self):
        """The measured consequence, as the lookup reads it: an unhashable key raises."""
        with self.assertRaises(TypeError):
            {"mldsa65": "ML-DSA-65"}.get(["mldsa65"])


class TestTheGuardItself(unittest.TestCase):
    def setUp(self):
        import sys
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_member
        self.is_member = is_member

    def test_unhashable_values_answer_False_instead_of_raising(self):
        for wert in ([], {}, set(), [1], {"a": 1}):
            with self.subTest(wert=repr(wert)):
                self.assertFalse(self.is_member(wert, {"ok", "fail"}))

    def test_a_real_member_still_answers_True(self):
        # The anti-parity half of the guard: one that always returned False would pass everything
        # above and quietly accept every value as invalid.
        self.assertTrue(self.is_member("ok", {"ok", "fail"}))
        self.assertTrue(self.is_member("k", {"k": 1}))

    def test_non_members_answer_False(self):
        self.assertFalse(self.is_member("nope", {"ok", "fail"}))

    def test_it_works_unchanged_on_containers_that_do_not_hash(self):
        # So routing tuple/list sites through it later is a no-op, not a behaviour change.
        self.assertTrue(self.is_member("ok", ("ok", "fail")))
        self.assertFalse(self.is_member([], ["ok"]))


class TestScannerOnADisposableTree(unittest.TestCase):
    def test_it_reads_real_files_not_only_strings(self):
        # The tree scan above walks files; if the file-reading path were broken it would report an
        # empty list and look like a clean tree. Same vacuity, one layer down.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "planted.py"
            p.write_text('_A = {"x"}\ndef f(o):\n    return o.get("k") in _A\n', encoding="utf-8")
            self.assertEqual(len(unguarded_membership_sites(p.read_text(encoding="utf-8"), str(p))), 1)


if __name__ == "__main__":
    unittest.main()


class TestTheGuardCannotRaiseItself(unittest.TestCase):
    """REGRESSION for the finding the mandatory review lane raised on 2026-08-26 (verdict REJECT).

    A guard whose entire contract is "never raises" must not have a shape that raises. The first
    version used `isinstance(value, Hashable)` alone, and that tests whether `__hash__` EXISTS, not
    whether calling it succeeds — a tuple inherits `__hash__` and only fails once it hashes its
    elements. Not reachable from `json.loads` today, which is a property of the CALLERS, not of this
    function; a guard that is only correct because of what happens to be passed to it is not a guard.
    """

    def setUp(self):
        import sys
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_member
        self.is_member = is_member

    def test_a_tuple_holding_an_unhashable_element_does_not_raise(self):
        self.assertFalse(self.is_member(("a", []), {"ok"}))
        self.assertFalse(self.is_member((1, {}), {"ok"}))
        self.assertFalse(self.is_member(((),[]), {"ok"}))

    def test_the_reviewers_dict_example_was_already_covered(self):
        # Recorded because half the finding did NOT hold: `dict.__hash__` is None, so the isinstance
        # check rejects it before any hashing. Keeping the measurement stops the wrong half from
        # being "re-discovered" later as a new defect.
        from collections.abc import Hashable
        self.assertFalse(isinstance({"a": []}, Hashable))
        self.assertFalse(self.is_member({"a": []}, {"ok"}))

    def test_anti_parity_a_hashable_tuple_still_works_normally(self):
        # Without this, an is_member that returned False for every tuple would pass the test above.
        self.assertTrue(self.is_member(("a", "b"), {("a", "b"), "x"}))
        self.assertFalse(self.is_member(("a", "b"), {"x"}))
