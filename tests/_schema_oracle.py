"""A JSON Schema oracle that reads `pattern` the way the schemas mean it: as ECMA-262.

python-jsonschema evaluates `pattern` with Python's `re.search`, and two differences reach the patterns
in schemas/. `$` in Python matches before a trailing newline, ECMA-262 only at the end of the input.
`\\d` in Python matches every Unicode decimal digit, ECMA-262 only 0-9. Measured 2026-09-26: jsonschema
4.26 accepted "a"*64 + "\\n" for `^[0-9a-f]{64}$` and "0.1.\\u0663" for `^0\\.1\\.\\d+$`, so a
generator using it as the oracle could not see either reading in a validator.

The oracle translates exactly those constructs and refuses a pattern that uses anything else, so a new
pattern cannot be read in the wrong dialect without a test saying so. The translation was compared
with node 22's RegExp (with the `u` flag) on every pattern of the five predicate schemas and eighteen
probe strings, and agreed on all of them; plain `re.search` disagreed on six.

Also here, because every generator over these schemas needs them: the leaf paths of a document, a
copy with one value replaced, and the values a generator tries at a leaf.
"""
from __future__ import annotations

import copy
import functools
import re

import jsonschema

#: The whole vocabulary the oracle translates: literals, `\\d`, `\\.`, bracket ranges, counted and plain
#: quantifiers, plain groups. Anything else (an alternation, an inline flag, `\\w`, a lookaround) is refused.
#: The first version checked only for other backslash escapes and let `(?i)` through; its own test caught it.
_VOCABULARY = re.compile(r"(?:\\[d.]|\[[0-9A-Za-z-]+\]|\{[0-9]+(?:,[0-9]*)?\}|[+*?()]|[0-9A-Za-z:-])*")


@functools.lru_cache(maxsize=None)
def ecma_pattern(pattern: str) -> re.Pattern:
    """`pattern` as ECMA-262 reads it, in Python syntax. Only the shapes the schemas use are accepted."""
    body = pattern[1:-1]
    if not (pattern.startswith("^") and pattern.endswith("$") and _VOCABULARY.fullmatch(body)
            and "(?" not in body):
        raise ValueError(f"the ECMA oracle does not translate {pattern!r}; extend it deliberately")
    # The vocabulary is lexical: `a{3,1}`, `[9-0]` or an unbalanced group pass it, and so does a count
    # Python's `re` cannot hold (`{4294967295}` is its MAXREPEAT; node compiles it). Whatever Python
    # cannot compile, the oracle does not translate, with the error it promises (gate run 2 on
    # 63ddaaab, lens B, 228bc-2B-01/02: an OverflowError and a re.error escaped instead).
    try:
        return re.compile(r"\A" + body.replace(r"\d", "[0-9]") + r"\Z")
    except (re.error, OverflowError) as exc:
        raise ValueError(f"the ECMA oracle does not translate {pattern!r} ({exc}); extend it "
                         "deliberately") from exc


def _pattern(validator, pattern, instance, schema):
    if validator.is_type(instance, "string") and not ecma_pattern(pattern).search(instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r} (read as ECMA-262)")


EcmaValidator = jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": _pattern})


def schema_accepts(instance, schema) -> bool:
    return EcmaValidator(schema).is_valid(instance)


#: Values of the wrong type. Every leaf is tried with each of them.
CONFUSED = {"null": None, "true": True, "zero": 0, "minus one": -1, "a float": 1.5, "empty string": "",
            "empty list": [], "list of null": [None], "empty object": {}, "object with empty key": {"": None},
            "a string": "x"}


def bent_strings(value: str) -> dict:
    """Strings of the right type that a pattern must refuse: a trailing newline, an Arabic-Indic digit in
    place of the first ASCII digit, upper case in place of lower-case hex."""
    out = {"trailing newline": value + "\n"}
    m = re.search(r"[0-9]", value)
    if m:
        out["arabic-indic digit"] = value[:m.start()] + chr(0x0660 + int(m.group())) + value[m.end():]
    if re.search(r"[a-f]", value) and value.lower() == value:
        out["upper case"] = value.upper()
    return out


def leaf_paths(o, pre=()):
    """Every path below the root, containers included."""
    if pre:
        yield pre
    if isinstance(o, dict):
        for k, v in o.items():
            yield from leaf_paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaf_paths(v, pre + (i,))


def dict_paths(o, pre=()):
    """Every path, the root `()` included, at which the document holds an object."""
    if isinstance(o, dict):
        yield pre
        for k, v in o.items():
            yield from dict_paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from dict_paths(v, pre + (i,))


def get_at(o, path):
    for k in path:
        o = o[k]
    return o


def set_at(o, path, value):
    o = copy.deepcopy(o)
    cur = o
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return o


def with_key(o, path, key, value):
    o = copy.deepcopy(o)
    get_at(o, path)[key] = value
    return o


def mutations(base):
    """(label, path, mutated document) for every leaf with every confused value and, for a string leaf,
    every bent string; and for every object one added key."""
    for path in leaf_paths(base):
        leaf = get_at(base, path)
        variants = dict(CONFUSED)
        if isinstance(leaf, str):
            variants.update(bent_strings(leaf))
        for label, value in variants.items():
            yield label, path, set_at(base, path, value)
    for path in dict_paths(base):
        yield "an added key", path, with_key(base, path, "zzUndeclared", 1)
