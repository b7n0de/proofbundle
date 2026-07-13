# Baseline vor der 3.1.1-Audit-Runde (Ziel 3.1.3)

Erhoben 2026-07-13 (Farmer, frischer `git fetch --all --tags`, installierte 3.1.2 im Repo-venv).
Konsolidierter Auftrag: `proofbundle_3.1.1_audit_konsolidierte_umsetzungsprompt_live_20260713.md` (§2.1).

| Punkt | Wert | Beleg |
|---|---|---|
| current branch | `p0/3.1.3-correctness` (von `main`) | `git branch --show-current` |
| current commit | `bdea3533ec43497d106c15067257edec716124e0` | `git rev-parse HEAD` |
| latest tag | `v3.1.2` | `git describe --tags --abbrev=0` |
| package version | `3.1.2` | `proofbundle --version` |
| PyPI version | `3.1.2` (Upload 2026-07-13T11:37) | §1-Tabelle des Auftrags, live erhoben |
| SPEC revision | `2026-07-11` | `proofbundle.SPEC_REVISION` |
| test count | 920 Testfunktionen | `grep -rc "def test_" tests/` |
| open PR count | 0 | `gh pr list --state open` |
| open issue count | 5 (#55, #27, #26, #24, #7 — Roadmap, keine Blocker) | `gh issue list --state open` |
| website version | 3.1.2 (Homepage-Sync PR#1856 vom 13.07.) | 2bedone `office/governance/proofbundle_facts.json` |

## Befundstatus live reproduziert (gegen installierte 3.1.2)

| Befund | Status | Repro |
|---|---|---|
| A-P0-1 Root+Tree-Size atomar | **OPEN** | `TREE_CONTEXT`/`trustedCheckpoints` in policy.py: `False False` |
| A-P0-2 expired eval policy | **Eval OPEN**, Decision GESCHLOSSEN | `policy_expired` in `evaluate_policy`: `False`; in `evaluate_decision_policy`: `True` |
| A-P0-3 decision aud/nonce | GESCHLOSSEN (Regression sichern) | fail-closed-Pfad in `verify_decision_receipt`: `True` |
| A-P0-4 policyPurpose | **OPEN** | `policyPurpose` in policy.py: `False` |
| A-P0-5 policy/root metadata | **TEILWEISE** | malformed `trusted_roots` = stiller Nichtmatch (`continue` in evaluate_policy); Overlay kann `requiresIdentityOverlay` überschreiben (`inst.update(overlay)` nach dem Setzen) |
| A-P0-6 website sync | Version aktuell synchron (3.1.2 seit PR#1856); **CI-Drift-Gate pb-seitig fehlt** | separates Website-Increment (§10) |

## §2.2 PR-Null-Gate

0 offene PRs → 0 unklassifizierte, 0 veraltete Drafts, 0 ungeklärte Security-/Dependabot-PRs.
Abschlussbedingung erfüllt; `OPEN_PR_CLOSURE_REPORT.md` entfällt inhaltlich (dieser Abschnitt ist der Nachweis).
