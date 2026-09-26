"""The Rust verifier refuses every `relations` section the Python policy loader refuses.

WHERE THIS COMES FROM. Measured 2026-09-26 on main 1f7a62d2, corpus case
`relation-signer-cross-issuer-unauthorized`, with one field of its policy changed:

| policy change | Python `decision verify --policy` | Rust `verify-relation --policy` |
|---|---|---|
| relation_signer mode "bogus" | exit 2, mode must be one of ['same-key', 'pinned'] | exit 0, reasons [] |
| pinned key = the identity point | exit 2, low-order Ed25519 point | exit 3, RELATION_SIGNER_UNAUTHORIZED |

The first row is a fail-open in the second verifier: same bytes, refuse against accept. The Rust
reader checked the policy's hull (unknown fields, schema, policy_id) and read the section it
evaluates without judging it, although its own comment said both must get Python's verdict.

WHAT IS PINNED. Each way `policy.load_policy` refuses a `relations` section, run through both
verifiers on the same receipt: both exit 2, and the Rust reason carries Python's wording. The
original policy is the positive control: both exit 3 with RELATION_SIGNER_UNAUTHORIZED, so a refusal
below cannot come from a case that fails for any other reason.

AND THE WHOLE REASON, NOT A FRAGMENT (gate run 1 on bb231dbf, 224-1A-01/02, 224-1B-01/02, 224-1C-01).
The first version compared a fragment of each reason over 19 cases with one defect each. A generated
corpus now varies every field of the section and of a rule over thirteen JSON values, names a key the
hard ways (quotes of both kinds, a backslash, a tab, 300 characters), fills every hull section
completely, and pairs defects in both orders; the Rust reason must equal `load_policy`'s message
character for character. The hull of every section is judged in Python's order, before any value.
Measured: 337 policies, 321 refused by both with the same words; the binary of bb231dbf differs on
108 of them.

WHAT IS NOT PINNED, and why it is named here. A policy malformed OUTSIDE `relations` (for example a
`merkle.trusted_roots` entry that is not base64) is refused by Python and still evaluated by Rust:
measured on the same case, Python exit 2, Rust exit 3. The Rust reader does not evaluate those
sections, and porting all of `load_policy` is its own change. `test_a_section_rust_does_not_read_
is_still_a_named_gap` measures that the gap is still there, so the day it closes this file says so.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CASE = REPO / "conformance" / "relation" / "relation-signer-cross-issuer-unauthorized"
RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"
IDENTITY_B64 = base64.b64encode(b"\x01" + b"\x00" * 31).decode("ascii")


def _rust_binary():
    """Same lookup as tests/test_lauf11_l1_l4_rust_strukturbudget_und_kreuzvergleich.py."""
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


def _mutate(change):
    policy = json.loads((CASE / "policy.json").read_text(encoding="utf-8"))
    change(policy)
    return policy


def _set_rule(rule):
    def change(p):
        p["relations"]["relation_signer"]["supersedes"] = rule
    return change


def _set(key, value):
    def change(p):
        p["relations"][key] = value
    return change


# (label, change, fragment both reasons must carry)
REFUSED = [
    ("unknown mode", _set_rule({"mode": "bogus"}), "mode must be one of ['same-key', 'pinned']"),
    ("mode missing", _set_rule({"keys": [IDENTITY_B64]}), "mode must be one of"),
    ("same-key with keys", _set_rule({"mode": "same-key", "keys": []}), "takes no 'keys'"),
    ("pinned without keys", _set_rule({"mode": "pinned"}), "needs a non-empty 'keys' list"),
    ("pinned with an empty list", _set_rule({"mode": "pinned", "keys": []}), "needs a non-empty"),
    ("a key that is not base64", _set_rule({"mode": "pinned", "keys": ["!!"]}), "is not valid base64"),
    ("a short key", _set_rule({"mode": "pinned", "keys": [base64.b64encode(b"\x01" * 16).decode()]}),
     "must decode to 32 bytes, got 16"),
    ("a low-order key", _set_rule({"mode": "pinned", "keys": [IDENTITY_B64]}), "low-order Ed25519 point"),
    ("a non-canonical key",
     _set_rule({"mode": "pinned", "keys": [base64.b64encode(((1 << 255) - 18).to_bytes(32, "little")).decode()]}),
     "non-canonical Ed25519 encoding"),
    ("an extra field in a rule", _set_rule({"mode": "same-key", "extra": 1}), "unknown field(s) in"),
    ("a rule that is no object", _set_rule("pinned"), "must be a JSON object"),
    ("an unknown relation name",
     lambda p: p["relations"]["relation_signer"].update({"replaces": {"mode": "same-key"}}),
     "is not a relation name out of"),
    ("reject_superseded as text", _set("reject_superseded", "false"), "must be a boolean"),
    ("reject_retracted as a number", _set("reject_retracted", 1), "must be a boolean"),
    ("resolution list empty", _set("require_relation_resolution", []), "must be a non-empty list"),
    ("resolution names an unknown relation", _set("require_relation_resolution", ["replaces"]),
     "must be a non-empty list"),
    ("target not hex", _set("require_relation_target", {"supersedes": "xyz"}), "64-char lowercase hex"),
    ("target list empty", _set("require_relation_target", {"supersedes": []}), "must not be an empty list"),
    ("target for an unknown relation", _set("require_relation_target", {"replaces": "a" * 64}),
     "is not a relation name out of"),
]


_VALUES = {"null": None, "true": True, "false": False, "zero": 0, "one": 1, "a float": 1.5,
           "empty string": "", "a string": "x", "empty list": [], "list of a string": ["x"],
           "list of null": [None], "empty object": {}, "an object": {"a": 1}}
# Key names a message has to render: quotes of both kinds, a backslash, a control character, a name over
# the 256-character rendering bound, a non-ASCII letter. NAMED LIMIT (see py_str_repr in main.rs): Python
# decides which non-ASCII characters it escapes by the Unicode tables; this corpus stays within Latin-1.
_NAMES = ["extra", "it's", 'say "x"', "both ' and \"", "back\\slash", "tab\there", "k" * 300, "é",
          "aa", "zz"]
_NONCANONICAL_B64 = base64.b64encode(((1 << 255) - 18).to_bytes(32, "little")).decode()
_SHORT_B64 = base64.b64encode(b"\x01" * 16).decode()
# Every key each hull section allows, with a value `load_policy` accepts: Rust must know the same keys.
_FULL_SECTIONS = {
    "allowed_issuers": [],
    "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": False},
    "merkle": {"required_hash_alg": "sha256", "require_authenticated_root": False, "trusted_roots": [],
               "trusted_checkpoints": []},
    "sd_jwt": {"require_key_binding_when_cnf_present": False, "expected_aud": None, "require_nonce": False,
               "max_iat_age_seconds": None, "expected_vct": None},
    "status": {"reject_self_issued": False, "allowed_status_authorities": []},
    "assurance": {"minimum_level": None, "reject_self_attested_without_prereg": False},
    "anchors": {"require_anchor": None, "require_anchor_target": None, "allow_pending": False,
                "trusted_tsa_roots": [], "bitcoin_block_headers": {}, "trusted_tsa_policy_oids": []},
    "decision_receipt": {"trusted_decision_makers": [], "allowed_decision_types": [], "allowed_verdicts": [],
                         "required_evidence_relations": [], "accepted_predicate_types": [],
                         "require_policy_digest": False, "require_external_anchor": False,
                         "allow_pending": False, "require_audience": False, "require_nonce": False,
                         "require_not_checked": False, "require_decision_change_conditions": False,
                         "require_trace_context": False, "allow_raw_inputs": False},
}


def _generated_policies(base: dict) -> list:
    """(label, policy) pairs around the corpus policy: every relations field and every rule field with
    every JSON type, unknown names at every level of the hull, each hull section complete, and pairs of
    defects in both orders, because a pair is where the two orders of checking part."""
    import copy as _copy
    out = []

    def add(label, change):
        p = _copy.deepcopy(base)
        change(p)
        out.append((label, p))

    good_key = base["relations"]["relation_signer"]["supersedes"]["keys"][0]
    for key in ("require_relation_resolution", "reject_superseded", "reject_retracted", "relation_signer",
                "require_relation_target"):
        for vl, v in _VALUES.items():
            add(f"relations.{key} = {vl}", lambda p, k=key, v=v: p["relations"].__setitem__(k, v))
    for vl, v in _VALUES.items():
        add(f"relations = {vl}", lambda p, v=v: p.__setitem__("relations", v))
        add(f"rule = {vl}", lambda p, v=v: p["relations"]["relation_signer"].__setitem__("supersedes", v))
        add(f"mode = {vl}", lambda p, v=v: p["relations"]["relation_signer"]["supersedes"].__setitem__("mode", v))
        add(f"keys = {vl}", lambda p, v=v: p["relations"]["relation_signer"]["supersedes"].__setitem__("keys", v))
        add(f"keys = [{vl}]",
            lambda p, v=v: p["relations"]["relation_signer"]["supersedes"].__setitem__("keys", [v]))
        add(f"target = {vl}", lambda p, v=v: p["relations"].__setitem__("require_relation_target",
                                                                          {"supersedes": v}))
        add(f"resolution = [{vl}]",
            lambda p, v=v: p["relations"].__setitem__("require_relation_resolution", [v]))
    for kl, keys in (("low-order", [IDENTITY_B64]), ("non-canonical", [_NONCANONICAL_B64]),
                     ("short", [_SHORT_B64]), ("not base64", ["!!"]), ("good then low-order",
                                                                         [good_key, IDENTITY_B64])):
        add(f"keys {kl}", lambda p, k=keys: p["relations"]["relation_signer"]["supersedes"].__setitem__("keys", k))
    for name in _NAMES:
        short = name if len(name) < 20 else name[:10] + "..."
        add(f"unknown top field {short!r}", lambda p, n=name: p.__setitem__(n, 1))
        add(f"unknown relations field {short!r}", lambda p, n=name: p["relations"].__setitem__(n, 1))
        add(f"unknown rule field {short!r}",
            lambda p, n=name: p["relations"]["relation_signer"]["supersedes"].__setitem__(n, 1))
        add(f"relation name {short!r}",
            lambda p, n=name: p["relations"]["relation_signer"].__setitem__(n, {"mode": "same-key"}))
        add(f"target name {short!r}",
            lambda p, n=name: p["relations"].__setitem__("require_relation_target", {n: "a" * 64}))
    for section, full in _FULL_SECTIONS.items():
        add(f"{section} complete", lambda p, s=section, f=full: p.__setitem__(s, _copy.deepcopy(f)))
        if isinstance(full, dict):
            add(f"{section} with an unknown field",
                lambda p, s=section, f=full: p.__setitem__(s, {**_copy.deepcopy(f), "zz_unknown": 1}))
    add("allowed_issuers entry with an unknown field", lambda p: p.__setitem__("allowed_issuers", [{"zz": 1}]))
    add("checkpoint with an unknown field", lambda p: p.__setitem__("merkle", {"trusted_checkpoints": [{"zz": 1}]}))
    add("decision maker with an unknown field",
        lambda p: p.__setitem__("decision_receipt", {"trusted_decision_makers": [{"zz": 1}]}))
    for vl, v in _VALUES.items():
        add(f"schema = {vl}", lambda p, v=v: p.__setitem__("schema", v))
        add(f"policy_id = {vl}", lambda p, v=v: p.__setitem__("policy_id", v))
    add("schema v0.1", lambda p: p.__setitem__("schema", "proofbundle/trust-policy/v0.1"))
    add("decision_receipt under v0.1",
        lambda p: p.update({"schema": "proofbundle/trust-policy/v0.1", "decision_receipt": {}}))
    add("policy_id missing", lambda p: p.pop("policy_id"))
    add("decision_receipt under v0.1 and policy_id missing",
        lambda p: (p.update({"schema": "proofbundle/trust-policy/v0.1", "decision_receipt": {}}),
                   p.pop("policy_id")))
    # pairs of defects, in both orders: two rules, or a rule and another field
    rules = {"unknown field": ("supersedes", {"mode": "same-key", "extra": 1}),
             "bad mode": ("supersedes", {"mode": "bogus"}),
             "bad relation name": ("replaces", {"mode": "same-key"}),
             "empty keys": ("supersedes", {"mode": "pinned", "keys": []}),
             "low-order key": ("supersedes", {"mode": "pinned", "keys": [IDENTITY_B64]}),
             "rule not an object": ("supersedes", "pinned")}
    renames = {"supersedes": "revises", "replaces": "replaced"}
    for a, (name_a, rule_a) in rules.items():
        for b, (name_b, rule_b) in rules.items():
            if a == b:
                continue
            second = renames[name_b] if name_b == name_a else name_b
            add(f"two rules: {a}, then {b}",
                lambda p, na=name_a, ra=rule_a, nb=second, rb=rule_b:
                p["relations"].__setitem__("relation_signer", {na: ra, nb: rb}))
    others = {"resolution empty": lambda p: p["relations"].__setitem__("require_relation_resolution", []),
              "boolean as text": lambda p: p["relations"].__setitem__("reject_superseded", "false"),
              "target list empty": lambda p: p["relations"].__setitem__("require_relation_target",
                                                                       {"supersedes": []}),
              "policy_id missing": lambda p: p.pop("policy_id"),
              "schema v0.1": lambda p: p.__setitem__("schema", "proofbundle/trust-policy/v0.1"),
              "unknown top field": lambda p: p.__setitem__("zz", 1),
              "unknown relations field": lambda p: p["relations"].__setitem__("zz", 1),
              "unknown signature field": lambda p: p.__setitem__("signature", {"zz": 1})}
    for a, (name_a, rule_a) in rules.items():
        for o, change in others.items():
            add(f"rule with {a}, and {o}",
                lambda p, n=name_a, r=rule_a, c=change: (p["relations"].__setitem__("relation_signer", {n: r}),
                                                         c(p)))
    return out


class RustPolicyReaderJudgesTheRelationsSection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rust = _rust_binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs is missing or cargo is absent — "
                                    "the parity cases did NOT run (env_blocked, never green)")
        cls.pub = (CASE / "pub.b64").read_text(encoding="utf-8").strip()
        cls.case = json.loads((CASE / "case.json").read_text(encoding="utf-8"))

    def _both(self, policy: dict):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            related = []
            for rel, rpub in zip(self.case["related"], self.case["relatedPubs"]):
                related += ["--with-related", str(CASE / rel), "--related-pub", rpub]
            py = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); from proofbundle.cli import main; "
                 "sys.exit(main(sys.argv[1:]))" % str(REPO / "src"),
                 "decision", "verify", str(CASE / "receipt.json"), "--pub", self.pub, *related,
                 "--policy", str(path)],
                capture_output=True, text=True, timeout=120)
            rs = subprocess.run([str(self.rust), "verify-relation", str(CASE / "receipt.json"), self.pub,
                                 *related, "--policy", str(path)],
                                capture_output=True, text=True, timeout=120)
        return py, rs

    def test_positive_control_the_corpus_policy_is_unmet_in_both(self):
        py, rs = self._both(_mutate(lambda p: None))
        self.assertEqual(py.returncode, 3, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 3, rs.stdout + rs.stderr)
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", rs.stdout)

    def test_every_malformed_relations_section_is_refused_by_both_for_the_same_reason(self):
        for label, change, fragment in REFUSED:
            with self.subTest(case=label):
                py, rs = self._both(_mutate(change))
                self.assertEqual(py.returncode, 2, py.stdout + py.stderr)
                self.assertIn(fragment, py.stdout + py.stderr)
                self.assertEqual(rs.returncode, 2, rs.stdout + rs.stderr)
                self.assertIn(fragment, rs.stderr)

    def test_a_generated_corpus_gets_the_same_verdict_in_the_same_words(self):
        """Gate run 1 on bb231dbf: the 19 cases above compare a FRAGMENT of each reason, each with one
        defect. Lens A built 101 sections: every verdict agreed, and 7 named different defects, always
        where two defects met (224-1A-01); lens C found the weak-key reason in Rust's own words
        (224-1C-01); lens A and B found key names and values rendered as JSON (224-1A-02, 224-1B-02);
        lens B found no case for a section given as a scalar (224-1B-01). So the corpus is generated,
        defects are combined, and the WHOLE reason is compared with `policy.load_policy`'s."""
        sys.path.insert(0, str(REPO / "src"))
        from proofbundle.policy import PolicyError, load_policy
        base = json.loads((CASE / "policy.json").read_text(encoding="utf-8"))
        cases = _generated_policies(base)
        self.assertGreater(len(cases), 300, "the generator produced too little to hold anything")
        refused_by_both, mismatches = 0, []
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            for label, policy in cases:
                try:
                    load_policy(policy)
                    python = None
                except PolicyError as exc:
                    python = str(exc)
                path.write_text(json.dumps(policy), encoding="utf-8")
                rs = subprocess.run([str(self.rust), "verify-relation", str(CASE / "receipt.json"), self.pub,
                                     "--policy", str(path)], capture_output=True, text=True, timeout=60)
                prefix = "error: bad --policy: "
                rust = rs.stderr.strip()[len(prefix):] if rs.stderr.startswith(prefix) else None
                if rust is not None and rs.returncode != 2:
                    mismatches.append(f"{label}: Rust named a policy error but exited {rs.returncode}")
                if python != rust:
                    mismatches.append(f"{label}:\n  python {python!r}\n  rust   {rust!r}")
                refused_by_both += python is not None and rust is not None
        self.assertGreater(refused_by_both, 250, "too few refusals were compared")
        self.assertEqual(mismatches, [], "\n".join(mismatches[:20]))

    def test_the_rust_hull_knows_the_same_keys_as_python(self):
        """The corpus shows Rust accepts every key Python allows in each hull section; this shows it
        allows no more, by reading the constants in main.rs (they are data, not logic)."""
        import re
        sys.path.insert(0, str(REPO / "src"))
        from proofbundle import policy
        text = (RUST_DIR / "src" / "main.rs").read_text(encoding="utf-8")

        def konstante(name):
            m = re.search(rf"const {name}: &\[&str\] = &\[(.*?)\];", text, re.S)
            self.assertIsNotNone(m, name)
            return set(re.findall(r'"([^"]+)"', m.group(1)))

        self.assertEqual(konstante("POLICY_TOP_KEYS"), policy._TOP_KEYS)
        self.assertEqual(konstante("POLICY_RELATIONS_KEYS"), policy._RELATIONS_KEYS)
        self.assertEqual(konstante("POLICY_ISSUER_KEYS"), policy._ISSUER_KEYS)
        self.assertEqual(konstante("POLICY_CHECKPOINT_KEYS"), policy._CHECKPOINT_KEYS)
        self.assertEqual(konstante("POLICY_DECISION_MAKER_KEYS"), policy._DECISION_MAKER_KEYS)
        block = re.search(r"const POLICY_SEKTIONEN: &\[\(&str, &\[&str\]\)\] = &\[(.*?)\n\];", text, re.S)
        self.assertIsNotNone(block)
        sektionen = {}
        for m in re.finditer(r'\(\s*"(\w+)",\s*&\[(.*?)\]', block.group(1), re.S):
            sektionen[m.group(1)] = set(re.findall(r'"([^"]+)"', m.group(2)))
        self.assertEqual(sektionen, {"signature": policy._SIG_KEYS, "merkle": policy._MERKLE_KEYS,
                                     "sd_jwt": policy._SDJWT_KEYS, "status": policy._STATUS_KEYS,
                                     "assurance": policy._ASSURANCE_KEYS, "anchors": policy._ANCHORS_KEYS,
                                     "decision_receipt": policy._DECISION_KEYS})
        # and in Python's order, because the first unknown field found is the one reported
        self.assertEqual(list(sektionen), ["signature", "merkle", "sd_jwt", "status", "assurance", "anchors",
                                           "decision_receipt"])

    def test_a_section_rust_does_not_read_is_still_a_named_gap(self):
        """Counter-direction, measured rather than assumed: the gap named in the module docstring."""
        py, rs = self._both(_mutate(lambda p: p.update({"merkle": {"trusted_roots": ["not base64!"]}})))
        self.assertEqual(py.returncode, 2, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 3, "the Rust reader now judges the merkle section; update the "
                                           "docstring and the parity registry: " + rs.stdout + rs.stderr)


if __name__ == "__main__":
    unittest.main()
