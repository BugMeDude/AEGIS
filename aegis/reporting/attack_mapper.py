"""MITRE ATT&CK mapping for security findings.

Maps each AEGIS finding to MITRE ATT&CK Enterprise techniques
and generates ATT&CK Navigator-compatible layers.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import MITRE_ATTACK_MAP, VulnerabilityV3, Vulnerability


class ATTACKMapper:
    """Map AEGIS findings to MITRE ATT&CK framework."""

    TECHNIQUE_DETAILS = {
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "execution"},
        "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "execution"},
        "T1005": {"name": "Data from Local System", "tactic": "collection"},
        "T1204.001": {"name": "User Execution: Malicious Link", "tactic": "execution"},
        "T1498": {"name": "Network Denial of Service", "tactic": "impact"},
        "T1071.001": {"name": "Web Protocols", "tactic": "command-and-control"},
        "T1040": {"name": "Network Sniffing", "tactic": "discovery"},
        "T1528": {"name": "Steal Application Access Token", "tactic": "credential-access"},
    }

    @staticmethod
    def map_finding(vuln_type: str) -> str:
        """Map a vulnerability type to MITRE ATT&CK ID."""
        return MITRE_ATTACK_MAP.get(vuln_type, "")

    @staticmethod
    def map_finding_v3(finding: VulnerabilityV3) -> VulnerabilityV3:
        """Ensure a VulnerabilityV3 has its MITRE ID set."""
        if not finding.mitre_id:
            finding.mitre_id = MITRE_ATTACK_MAP.get(finding.type, "")
        return finding

    @classmethod
    def build_attack_matrix(cls, findings: list[VulnerabilityV3]) -> dict[str, list[VulnerabilityV3]]:
        """Group findings by MITRE ATT&CK technique ID."""
        matrix: dict[str, list[VulnerabilityV3]] = {}
        for f in findings:
            mid = cls.map_finding_v3(f).mitre_id
            if mid:
                matrix.setdefault(mid, []).append(f)
        return matrix

    @classmethod
    def generate_navigator_layer(cls, findings: list[VulnerabilityV3],
                                  name: str = "AEGIS Findings") -> str:
        """Generate a MITRE ATT&CK Navigator layer JSON string."""
        techniques = []
        for f in findings:
            mid = cls.map_finding_v3(f).mitre_id
            if mid and mid in cls.TECHNIQUE_DETAILS:
                techniques.append({
                    "techniqueID": mid,
                    "color": cls._severity_color(f.severity.value),
                    "comment": f"{f.type}: {f.endpoint} ({f.severity.value})",
                    "enabled": True,
                    "metadata": [{"name": "source", "value": f.source}],
                })

        layer = {
            "name": name,
            "versions": {
                "attack": "14.1",
                "navigator": "4.8.1",
                "layer": "4.4"
            },
            "description": f"AEGIS v3 security assessment findings mapped to ATT&CK",
            "domain": "enterprise-attack",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {"label": "Critical", "color": "#ff6666"},
                {"label": "High", "color": "#ff9966"},
                {"label": "Medium", "color": "#ffe766"},
                {"label": "Low", "color": "#8ec843"},
            ],
        }
        return json.dumps(layer, indent=2)

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "Critical": "#ff6666",
            "High": "#ff9966",
            "Medium": "#ffe766",
            "Low": "#8ec843",
            "Info": "#aabbcc",
        }.get(severity, "#aabbcc")
