# Residual risk, release 6.3.1

This file records findings for the 6.3.1 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.3.0](RESTRISIKO_630.md) and the records before it.

## Targets of 6.3.0 included in this release

[The residual-risk record of 6.3.0](RESTRISIKO_630.md) listed these items as targeted for 6.3.1.

- K3 to K10, the eight finding classes rated P1 by the candidate review of 6.3.0, in repository tools, examples, checks and interoperability code. K6, the core-layer gate reading an import alias at the wrong point, is changed for that case: a use is judged against every alias the same module gives the name. The limits of the gate that remain are listed below.
- The four additional P2 groups, as P2-1 to P2-4.
- Two trees that name a path twice and could share one release digest, as R13-3. The pre-tag tooling refuses such a tree.
- The nine further findings of the class search on `f6ea5cc3`, as A1, E1, D1, D2, D3, D4, E2, B1 and F1.
- The class of [the 6.2.0 record](RESTRISIKO_620.md) that a caller's own Python objects can make a never-raise surface raise, set to closed there within the measurement it names.

## Open after this release

### Eight public functions let a value without a bounded text form out raw

`tests/test_public_functions_render_a_value_from_outside_bounded.py` plants values that a naive rendering cannot handle, such as `10**5000`, a list nested past the recursion limit and an object whose `__repr__` raises, into every public function with a parameter. The functions below let such a value out as a raw exception. The test pins them by site as an upper bound, so it would not report one of them closing. Measured at `dfaa3079e5669d89e2f23aa09a5c0bdb05c54025` on 2026-10-20 with the sweep of that test: every pinned site still occurs.

| Function | Raw exception, at the innermost package frame |
|---|---|
| `_verdict.require_bool_verdict` | `RecursionError`, `ValueError`, the planted object's own exception, in `require_bool_verdict` |
| `evalclaim.build_eval_claim` | `RecursionError`, `ValueError`, in `build_eval_claim` |
| `evalclaim.check_freshness` | `ValueError`, in `check_freshness` |
| `intoto.to_eval_result_v02_predicate` | `RecursionError`, in `to_eval_result_v02_predicate` |
| `intoto.to_eval_result_v02_statement` | `RecursionError`, in `to_eval_result_v02_predicate` |
| `intoto.export_eval_result_v02_dsse` | `RecursionError`, in `to_eval_result_v02_predicate` |
| `sdjwt_issue.issue_sd_jwt` | `ValueError`, in `_make_disclosure` |
| `sdjwt_issue.present_with_key_binding` | `RecursionError`, `TypeError`, `ValueError`, in `present_with_key_binding` |

### Limits of the core-layer gate

`scripts/core_layer_gate.py` is a static check of the verification core, not a sandbox. Measured on 2026-10-20 at the gate of this release (the file is the same at `b7f6a3b0`, at `862f263d` and at `dfaa3079`), each case first run in a child process to show the guarded block running or the environment being read:

- It judges the bindings its analysis identifies within one module. A name the core imports from another module of the package, by a re-export (`from .other import os`) or a star import, is not followed to the binding there: `os.getenv` reached that way reads the environment and the gate stays green.
- A write to `TYPE_CHECKING` by assignment, through `module.__dict__`, through `vars(module)` or through `setattr`, also with a computed name, is counted. A write through `getattr(module, "__dict__")`, through `module.__setattr__`, `object.__setattr__` or a renamed `setattr` is not.
- `TYPE_CHECKING` made true without a write, by giving the `typing` module a class whose `TYPE_CHECKING` is a property, is not seen.
- A method name that reads the environment, such as `getenv`, on a receiver the gate cannot resolve (a loop target, an item of a list, an attribute of a constructed object) is not a finding; only the file methods and the path methods that read the working or the home directory are.
- A pure read of a namespace mapping in a module outside the core, such as `print(vars(x))`, counts as a possible change of `TYPE_CHECKING`, so every guarded import counts as running. This errs towards red.
- Code the gate does not parse, such as a string run by `exec`, is outside it.

A change of the gate for these forms is not part of this release.

### Limits of the reading of a path

A path-like argument under a path contract is read once at the call, and a `__fspath__` that raises or answers no `str` or `bytes` makes the value one that is no path, which each function answers as it answers `object()`. Measured at `a44a5667` with the 17 functions that carry such a contract. Three cases stay outside:

- A `__fspath__` that raises an exception outside the `Exception` family (`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`) passes, as it does on main.
- One object passed under two path arguments of one call is read once for each argument, so the two arguments can get different paths.
- Under the contract that takes a path or a loaded object (`adapters.inspect_ai.from_inspect_ai_log`), a loaded object is read with `hasattr`, which runs the caller's code, as it does on main. A loaded object whose `__fspath__` gives a valid path is read from that path.

### Repository tools

- `scripts/render_release.py` ends an HTML tag at a `>` inside a quoted attribute, so a target after such an attribute is neither bound nor checked, and it reads a link with an uppercase scheme (`HTTPS://`) as a path and refuses it. It also reads a link whose opening bracket is escaped with a backslash, and a link inside an HTML comment, as link targets, binds them to the described commit and checks them in its tree, so a text that shows link syntax literally is rewritten and a missing target is refused. Measured at `a44a5667`. No text of 6.3.1 has any of these forms.
- `conformance/common_vocabulary.compare` applies the rule for both sides only when both labels are observations, so a copy of an observation as a plain dict is read as an expectation.

## What this file does not say

It does not say that the findings above are the only open ones. The core-layer gate is a static check; a green result is limited to the forms it reads.
