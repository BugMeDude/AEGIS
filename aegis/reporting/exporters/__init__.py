"""Export adapters. SARIF 2.1.0 is implemented (standard, offline).

JIRA / Splunk / ELK adapters are intentionally not bundled — they require
operator-supplied endpoints + credentials and are environment-specific.
"""

from .sarif import to_sarif, write_sarif

__all__ = ["to_sarif", "write_sarif"]
