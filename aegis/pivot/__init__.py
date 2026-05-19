"""Post-exploit *validation* and *scoped* adjacent assessment.

Deliberately narrow, per AEGIS's own risk-mitigation policy ("detection and
validation focused — no live exploitation; nothing without operator
confirmation; no persistence/C2/lateral movement"):

  * :class:`ImpactValidator` — confirms a *already-detected* injection is real
    with a tiny, fixed number of bounded proof probes (boolean differential /
    a single short identifier such as the DB version). It NEVER enumerates or
    dumps rows/tables/columns. Gated behind the EXPERT auth tier + budget.

  * :class:`ScopedAssessment` — assesses ONLY additional target URLs the
    operator *explicitly* supplies, each re-passed through the safety gate.
    It does NOT auto-derive neighbours from a compromise, open tunnels, move
    laterally, or establish persistence.

These are authorised-pentest *impact evidencing* aids, not weaponisation.
"""

from .validator import ImpactValidator, ValidationResult
from .scope import ScopedAssessment

__all__ = ["ImpactValidator", "ValidationResult", "ScopedAssessment"]
