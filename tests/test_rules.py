"""
Every rule must:
  1. fire on every event in tests/fixtures/<rule name>/malicious.json
  2. stay silent on every event in tests/fixtures/<rule name>/benign.json

A rule with no fixtures fails the build, so nothing ships untested.
"""

import json
from pathlib import Path

import pytest

from engine import SigmaRule

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").rglob("*.yml"))
FIXTURES = ROOT / "tests" / "fixtures"


def _events(rule_path: Path, kind: str) -> list[dict]:
    path = FIXTURES / rule_path.stem / f"{kind}.json"
    assert path.exists(), f"Missing {kind} samples for {rule_path.name}: create {path.relative_to(ROOT)}"
    events = json.loads(path.read_text(encoding="utf-8"))
    assert events, f"{path.relative_to(ROOT)} is empty"
    return events


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_fires_on_malicious_samples(rule_path):
    rule = SigmaRule(rule_path)
    for event in _events(rule_path, "malicious"):
        assert rule.matches(event), f"MISSED: {rule.title} did not fire on: {event.get('_note', event)}"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_silent_on_benign_samples(rule_path):
    rule = SigmaRule(rule_path)
    for event in _events(rule_path, "benign"):
        assert not rule.matches(event), f"FALSE POSITIVE: {rule.title} fired on: {event.get('_note', event)}"
