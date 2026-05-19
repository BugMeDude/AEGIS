"""AI-driven executive narrative generation for penetration test reports.

Generates natural-language executive summaries, technical findings,
risk ratings, and remediation roadmaps from AEGIS scan results.
"""

from __future__ import annotations

import json
from typing import Any

from ..ai.router import ModelRouter
from ..config import AIProviderConfig
from ..models import RunReport, VulnerabilityV3, Campaign, Severity
from .attack_mapper import ATTACKMapper


class NarrativeGenerator:
    """Generate human-readable pen-test narratives from findings."""

    def __init__(self, ai_cfg: AIProviderConfig | None = None) -> None:
        self.router = ModelRouter(ai_cfg or AIProviderConfig())

    def generate_executive_summary(self, report: RunReport) -> str:
        """Generate executive summary from a RunReport."""
        d = report.to_dict()
        s = d["summary"]

        template = (
            f"AEGIS executed {s['total_attempts']} requests against "
            f"{len(report.targets)} target(s), achieving {s['throughput_rps']} req/s "
            f"with {s['success_rate']}% success rate. "
            f"The security assessment identified {len(report.vulnerabilities)} "
            f"finding(s), with top severity rated as {s['highest_severity']}. "
            f"Average latency was {s['overall_avg_ms']:.0f}ms."
        )
        return template

    def generate_finding_report(self, findings: list[VulnerabilityV3]) -> str:
        """Generate detailed finding descriptions."""
        lines = []
        for i, f in enumerate(findings, 1):
            lines.append(f"Finding #{i}: {f.type}")
            lines.append(f"  Severity: {f.severity.value}")
            lines.append(f"  Endpoint: {f.endpoint}")
            lines.append(f"  Description: {f.description}")
            lines.append(f"  Remediation: {f.remediation}")
            if f.mitre_id:
                lines.append(f"  MITRE ATT&CK: {f.mitre_id}")
            lines.append("")
        return "\n".join(lines)

    def generate_risk_matrix(self, findings: list[VulnerabilityV3]) -> dict:
        """Generate risk matrix with counts by severity."""
        matrix = {s.value: {"count": 0, "findings": []} for s in Severity}
        for f in findings:
            sev = f.severity.value if f.severity.value in matrix else "Info"
            matrix[sev]["count"] += 1
            matrix[sev]["findings"].append({
                "type": f.type,
                "endpoint": f.endpoint,
                "remediation": f.remediation,
            })
        return matrix

    def generate_remediation_roadmap(self, findings: list[VulnerabilityV3]) -> str:
        """Generate prioritized remediation roadmap."""
        by_severity = sorted(
            findings,
            key=lambda f: f.severity.rank,
            reverse=True,
        )

        lines = ["## Remediation Roadmap\n"]
        critical = [f for f in by_severity if f.severity == Severity.CRITICAL]
        high = [f for f in by_severity if f.severity == Severity.HIGH]
        medium = [f for f in by_severity if f.severity == Severity.MEDIUM]

        if critical:
            lines.append("### Immediate (Critical)")
            for f in critical:
                lines.append(f"- {f.type} at {f.endpoint}")
                lines.append(f"  - {f.remediation}")
        if high:
            lines.append("\n### Short-term (High)")
            for f in high:
                lines.append(f"- {f.type} at {f.endpoint}")
                lines.append(f"  - {f.remediation}")
        if medium:
            lines.append("\n### Medium-term (Medium)")
            for f in medium:
                lines.append(f"- {f.type} at {f.endpoint}")
                lines.append(f"  - {f.remediation}")

        return "\n".join(lines)

    def generate_full_report(self, report: RunReport,
                              findings_v3: list[VulnerabilityV3] | None = None) -> str:
        """Generate a complete penetration test report narrative."""
        v3 = findings_v3 or [
            VulnerabilityV3(
                type=v.type, description=v.description, severity=v.severity,
                endpoint=v.endpoint, remediation=v.remediation,
                evidence=v.evidence, source=v.source,
            )
            for v in report.vulnerabilities
        ]

        sections = [
            "# AEGIS v3 Penetration Test Report\n",
            "## Executive Summary\n",
            self.generate_executive_summary(report),
            "\n---\n",
            "## Risk Matrix\n",
            json.dumps(self.generate_risk_matrix(v3), indent=2),
            "\n---\n",
            "## MITRE ATT&CK Coverage\n",
            self._mitre_coverage_text(v3),
            "\n---\n",
            "## Technical Findings\n",
            self.generate_finding_report(v3),
            "\n---\n",
            self.generate_remediation_roadmap(v3),
            "\n---\n",
            "## Methodology\n",
            "All testing was performed using AEGIS v3, an autonomous API security "
            "testing platform. Testing included:\n"
            "- Passive security header analysis\n"
            "- Active vulnerability scanning (SQLi, XSS, SSRF, XXE, etc.)\n"
            "- Load/stress testing for performance assessment\n"
            "- AI-driven attack chain analysis\n"
            "- MITRE ATT&CK technique mapping\n",
        ]
        return "\n\n".join(sections)

    def _mitre_coverage_text(self, findings: list[VulnerabilityV3]) -> str:
        mapped = ATTACKMapper.build_attack_matrix(findings)
        lines = [f"This assessment covers {len(mapped)} MITRE ATT&CK techniques:\n"]
        for tid, fs in sorted(mapped.items()):
            info = ATTACKMapper.TECHNIQUE_DETAILS.get(tid, {})
            name = info.get("name", tid)
            tactic = info.get("tactic", "")
            lines.append(f"- **{tid}**: {name} ({tactic}) — {len(fs)} finding(s)")
        return "\n".join(lines)
