"""Scanner surface. The active scanners are implemented in ``aegis.offense.offense.OffensiveScanner`` (15+ vuln classes in one engine); this package re-exports them for a stable import path."""

from ..offense import OffensiveScanner, active_scan, active_scan_v3

__all__ = ["OffensiveScanner", "active_scan", "active_scan_v3"]
