"""
Convert every Sigma rule into ready to paste queries for Splunk, Microsoft
Sentinel / Defender XDR (KQL) and Elastic (Lucene), using sigma-cli.

Output goes to queries/<target>/<rule name>.txt. Run from the repo root:

    python scripts/convert_all.py

A rule that cannot be converted for a target is reported and skipped, so
one unsupported log source does not block the others.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").rglob("*.yml"))
OUT = ROOT / "queries"
SENTINEL_SECURITY = str(ROOT / "pipelines" / "sentinel_securityevent.yml")


def targets_for(rule: dict) -> dict[str, list[str]]:
    """Pick the right backend and pipelines for a rule's log source."""
    logsource = rule.get("logsource", {})
    targets = {
        "splunk": ["-t", "splunk", "-p", "splunk_windows"],
        "elastic_lucene": ["-t", "lucene", "-p", "ecs_windows"],
    }
    if logsource.get("service") == "security":
        targets["sentinel_kql"] = ["-t", "kusto", "-p", SENTINEL_SECURITY, "-p", "azure_monitor"]
    elif logsource.get("category") == "process_creation":
        targets["defender_xdr_kql"] = ["-t", "kusto", "-p", "microsoft_xdr"]
    return targets


def main() -> int:
    failures = 0
    for rule_path in RULES:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        for target, args in targets_for(rule).items():
            out_file = OUT / target / f"{rule_path.stem}.txt"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["sigma", "convert", *args, str(rule_path)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                failures += 1
                print(f"[skip] {rule_path.stem} -> {target}: {result.stderr.strip().splitlines()[-1]}")
                continue
            query = "\n".join(
                line for line in result.stdout.splitlines() if not line.startswith("Parsing Sigma rules")
            ).strip()
            out_file.write_text(query + "\n", encoding="utf-8")
            print(f"[ok]   {rule_path.stem} -> {target}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
