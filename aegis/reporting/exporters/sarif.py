"""SARIF 2.1.0 exporter.

SARIF is the OASIS-standard static/dynamic analysis interchange format
consumed by GitHub code-scanning, Azure DevOps, DefectDojo, etc. This is a
pure, defensive serialisation of AEGIS findings — no network, no side effects.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...models import RunReport

# AEGIS severity -> SARIF level + numeric security-severity (CVSS-ish bucket).
_LEVEL = {
    "Critical": ("error", "9.5"),
    "High": ("error", "8.0"),
    "Medium": ("warning", "5.5"),
    "Low": ("note", "3.0"),
    "Info": ("none", "0.0"),
}


def to_sarif(report: RunReport) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from a run report."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for v in report.vulnerabilities:
        sev = getattr(v.severity, "value", str(v.severity))
        level, sec = _LEVEL.get(sev, ("warning", "5.0"))
        rule_id = (v.type or "finding").strip().replace(" ", "-").lower()

        if rule_id not in rules:
            props: dict[str, Any] = {"security-severity": sec}
            cwe = getattr(v, "cwe", "")
            if cwe:
                props["cwe"] = cwe
            rules[rule_id] = {
                "id": rule_id,
                "name": v.type or "Finding",
                "shortDescription": {"text": (v.type or "Finding")[:120]},
                "fullDescription": {"text": v.description or v.type or ""},
                "help": {"text": v.remediation or "See description."},
                "defaultConfiguration": {"level": level},
                "properties": props,
            }

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": v.description or v.type or "Security finding"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.endpoint or "n/a"},
                },
            }],
            "properties": {
                "severity": sev,
                "source": getattr(v, "source", "aegis"),
                "remediation": v.remediation or "",
                "evidence": (getattr(v, "evidence", "") or "")[:600],
                "mitre_attack": getattr(v, "mitre_id", "") or "",
                "cve": getattr(v, "cve", "") or "",
                "confidence": getattr(v, "confidence", "") or "",
            },
        }
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AEGIS",
                    "informationUri": "https://github.com/BugMeDude/AEGIS",
                    "version": "3.0.0",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "properties": {
                "targets": report.targets,
                "started_at": report.started_at,
                "finished_at": report.finished_at,
            },
        }],
    }


def write_sarif(report: RunReport, path: str) -> str:
    """Serialise the report to a ``.sarif`` JSON file. Returns the path."""
    Path(path).write_text(json.dumps(to_sarif(report), indent=2),
                          encoding="utf-8")
    return path
