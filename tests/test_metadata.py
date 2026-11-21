"""
Quality gate for rule metadata, so every rule is something an analyst can
act on: who wrote it, how bad it is, what it maps to in ATT&CK, and when it
is expected to be wrong.
"""

import re
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").rglob("*.yml"))

REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTIC_TAG = re.compile(r"^attack\.[a-z]+(-[a-z]+)*$")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_there_are_rules():
    assert RULES, "No rules found under rules/"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_required_fields(rule_path):
    rule = _load(rule_path)
    missing = [f for f in REQUIRED if f not in rule]
    assert not missing, f"{rule_path.name} is missing: {missing}"
    assert rule["level"] in LEVELS
    assert rule["status"] in STATUSES
    uuid.UUID(str(rule["id"]))  # raises if not a valid UUID
    assert rule["falsepositives"], "List at least one known false positive (or 'Unknown')"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_attack_mapping(rule_path):
    tags = _load(rule_path)["tags"]
    assert any(TECHNIQUE_TAG.match(t) for t in tags), "Map the rule to at least one ATT&CK technique (attack.tXXXX)"
    assert any(TACTIC_TAG.match(t) and not TECHNIQUE_TAG.match(t) for t in tags), "Add at least one ATT&CK tactic tag"


def test_rule_ids_are_unique():
    ids = [_load(p)["id"] for p in RULES]
    assert len(ids) == len(set(ids)), "Two rules share the same id"
