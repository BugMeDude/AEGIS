"""Report writers and v3 enhanced reporting.

Re-exports classic reporting.py functions for backward compatibility.
"""

from __future__ import annotations

# Re-export classic reporting functions
from ..reporting_core import (  # type: ignore
    render_html,
    render_markdown,
    write_reports,
)

from .attack_mapper import ATTACKMapper
from .narrative import NarrativeGenerator

__all__ = [
    "render_html", "render_markdown", "write_reports",
    "ATTACKMapper", "NarrativeGenerator",
]
