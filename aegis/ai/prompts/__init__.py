"""Prompt library — organized by role/persona for the AI layer.

Each section contains system + user prompt templates for a specific
capability. All instruct strict JSON output.

Re-exports classic prompts for backward compatibility.
"""

from .classic import (
    NLP_SYSTEM,
    NLP_USER,
    PLANNER_SYSTEM,
    PLANNER_USER,
    SECURITY_SYSTEM,
    SECURITY_USER,
    SUMMARY_SYSTEM,
    SUMMARY_USER,
)
from .redteam import (
    ATTACK_VECTOR_SYSTEM,
    ATTACK_VECTOR_USER,
    CHAIN_SYSTEM,
    CHAIN_USER,
    MUTATION_SYSTEM,
    MUTATION_USER,
    PAYLOAD_SYSTEM,
    PAYLOAD_USER,
    RESPONSE_ANALYSIS_SYSTEM,
    RESPONSE_ANALYSIS_USER,
    STRATEGIST_SYSTEM,
    STRATEGY_USER,
)

__all__ = [
    "PLANNER_SYSTEM", "PLANNER_USER",
    "NLP_SYSTEM", "NLP_USER",
    "SECURITY_SYSTEM", "SECURITY_USER",
    "SUMMARY_SYSTEM", "SUMMARY_USER",
    "STRATEGIST_SYSTEM", "STRATEGY_USER",
    "ATTACK_VECTOR_SYSTEM", "ATTACK_VECTOR_USER",
    "PAYLOAD_SYSTEM", "PAYLOAD_USER",
    "MUTATION_SYSTEM", "MUTATION_USER",
    "CHAIN_SYSTEM", "CHAIN_USER",
    "RESPONSE_ANALYSIS_SYSTEM", "RESPONSE_ANALYSIS_USER",
]
