"""
A small, dependency light Sigma evaluator used to unit test rules against
sample events (JSON dictionaries).

It supports the parts of the Sigma specification used by simple, single
event rules:

  * selections written as a map (AND of fields) or a list of maps (OR)
  * list values (OR, or AND with the |all modifier)
  * modifiers: contains, startswith, endswith, all, re, cased
  * wildcards * and ? in plain string values
  * conditions with and / or / not, parentheses,
    "1 of name*", "all of name*", "1 of them", "all of them"

Case insensitive matching is the Sigma default and is used here unless the
|cased modifier is given. Correlation and aggregation rules (timeframe,
count) are out of scope: real SIEMs handle those, and they are tested
differently (see ROADMAP.md, week 5).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cased"}


class SigmaRuleError(ValueError):
    """Raised when a rule uses something this evaluator does not support."""


# --------------------------------------------------------------------------
# Field matching
# --------------------------------------------------------------------------

def _to_text(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _match_value(event_value: Any, pattern: Any, modifiers: list[str]) -> bool:
    if event_value is None:
        return pattern is None
    if pattern is None:
        return False

    cased = "cased" in modifiers
    text = _to_text(event_value)
    pat = _to_text(pattern)

    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        return re.search(pat, text, flags) is not None

    if not cased:
        text, pat = text.lower(), pat.lower()

    if "contains" in modifiers:
        return pat in text
    if "startswith" in modifiers:
        return text.startswith(pat)
    if "endswith" in modifiers:
        return text.endswith(pat)

    if "*" in pat or "?" in pat:
        return fnmatch.fnmatchcase(text, pat)
    return text == pat


def _match_field(event: dict, field_spec: str, expected: Any) -> bool:
    parts = field_spec.split("|")
    field, modifiers = parts[0], parts[1:]
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaRuleError(f"Unsupported modifier(s) {sorted(unknown)} on field '{field}'")

    event_value = event.get(field)
    values = expected if isinstance(expected, list) else [expected]
    results = (_match_value(event_value, v, modifiers) for v in values)
    return all(results) if "all" in modifiers else any(results)


def _match_selection(event: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list) and all(isinstance(item, dict) for item in selection):
        return any(_match_selection(event, item) for item in selection)
    raise SigmaRuleError("Keyword (full text) selections are not supported by this evaluator")


# --------------------------------------------------------------------------
# Condition parsing (recursive descent: or < and < not < primary)
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class _Condition:
    def __init__(self, condition: str, selections: dict[str, Any]):
        self.tokens = _TOKEN_RE.findall(condition)
        self.pos = 0
        self.selections = selections

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaRuleError("Unexpected end of condition")
        self.pos += 1
        return token

    def parse(self):
        node = self._or()
        if self._peek() is not None:
            raise SigmaRuleError(f"Unexpected token '{self._peek()}' in condition")
        return node

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()
            left = ("or", left, right)
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            left = ("and", left, right)
        return left

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._primary()

    def _primary(self):
        token = self._take()
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise SigmaRuleError("Missing closing parenthesis in condition")
            return node
        if token in ("1", "all") and self._peek() == "of":
            self._take()
            target = self._take()
            names = self._expand(target)
            return ("any" if token == "1" else "all", names)
        if token not in self.selections:
            raise SigmaRuleError(f"Condition references unknown selection '{token}'")
        return ("sel", token)

    def _expand(self, target: str) -> list[str]:
        if target == "them":
            names = [n for n in self.selections if not n.startswith("_")]
        else:
            names = [n for n in self.selections if fnmatch.fnmatchcase(n, target)]
        if not names:
            raise SigmaRuleError(f"'{target}' matches no selections")
        return names


def _evaluate(node, event: dict, selections: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "sel":
        return _match_selection(event, selections[node[1]])
    if kind == "not":
        return not _evaluate(node[1], event, selections)
    if kind == "and":
        return _evaluate(node[1], event, selections) and _evaluate(node[2], event, selections)
    if kind == "or":
        return _evaluate(node[1], event, selections) or _evaluate(node[2], event, selections)
    if kind == "any":
        return any(_match_selection(event, selections[n]) for n in node[1])
    if kind == "all":
        return all(_match_selection(event, selections[n]) for n in node[1])
    raise SigmaRuleError(f"Unknown condition node '{kind}'")


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

class SigmaRule:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        detection = dict(self.raw["detection"])
        if "timeframe" in detection:
            raise SigmaRuleError("Rules with a timeframe (aggregations) are not supported")
        condition = detection.pop("condition")
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        self.selections = detection
        self._tree = _Condition(condition, detection).parse()

    @property
    def title(self) -> str:
        return self.raw["title"]

    def matches(self, event: dict) -> bool:
        return _evaluate(self._tree, event, self.selections)
