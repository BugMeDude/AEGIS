"""Configuration loading and the responsible-use safety policy.

Precedence (lowest -> highest): built-in defaults < YAML file < environment
variables (``AEGIS_*``) < explicit CLI flags (applied by the caller).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml is a hard dep but degrade safely
    yaml = None

DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "aegis.yaml",
    Path.cwd() / "config.yaml",
    Path.home() / ".config" / "aegis" / "config.yaml",
]


@dataclass(slots=True)
class SafetyPolicy:
    """Responsible-use guardrails for this dual-use appsec tool.

    AEGIS will only generate sustained load against a target the operator has
    explicitly affirmed they are authorised to test. Caps stop an accidental
    typo from turning a load test into a denial-of-service event.
    """

    authorized: bool = False
    max_concurrency: int = 250
    max_duration_seconds: int = 600
    max_total_requests: int = 200_000
    # Hosts always allowed without the authorization affirmation (your own lab).
    local_allow: tuple[str, ...] = ("localhost", "127.0.0.1", "::1", "0.0.0.0")
    # If non-empty, ONLY these hosts (plus local_allow) may be targeted.
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] = ()


@dataclass(slots=True)
class OllamaConfig:
    host: str = "http://localhost:11434"
    model: str = "gemma4:31b-cloud"
    fallback_model: str = "gemma4:latest"
    timeout_seconds: float = 90.0
    temperature: float = 0.1
    enabled: bool = True


@dataclass(slots=True)
class AegisConfig:
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    safety: SafetyPolicy = field(default_factory=SafetyPolicy)
    report_dir: str = "aegis_reports"
    default_timeout: float = 15.0

    # ---- loading ---------------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "AegisConfig":
        cfg = cls()
        data: dict[str, Any] = {}

        chosen: Path | None = None
        if path:
            chosen = Path(path)
        else:
            for p in DEFAULT_CONFIG_PATHS:
                if p.is_file():
                    chosen = p
                    break

        if chosen and chosen.is_file() and yaml is not None:
            try:
                data = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
            except Exception:
                data = {}

        if "ollama" in data and isinstance(data["ollama"], dict):
            for k, v in data["ollama"].items():
                if hasattr(cfg.ollama, k):
                    setattr(cfg.ollama, k, v)
        if "safety" in data and isinstance(data["safety"], dict):
            for k, v in data["safety"].items():
                if hasattr(cfg.safety, k):
                    setattr(cfg.safety, k, tuple(v) if isinstance(v, list) else v)
        for k in ("report_dir", "default_timeout"):
            if k in data:
                setattr(cfg, k, data[k])

        cfg._apply_env()
        return cfg

    def _apply_env(self) -> None:
        env = os.environ
        if v := env.get("AEGIS_OLLAMA_HOST"):
            self.ollama.host = v
        if v := env.get("AEGIS_OLLAMA_MODEL"):
            self.ollama.model = v
        if v := env.get("AEGIS_REPORT_DIR"):
            self.report_dir = v
        if env.get("AEGIS_NO_AI") in ("1", "true", "yes"):
            self.ollama.enabled = False
        if env.get("AEGIS_AUTHORIZED") in ("1", "true", "yes"):
            self.safety.authorized = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ollama": asdict(self.ollama),
            "safety": {
                k: (list(v) if isinstance(v, tuple) else v)
                for k, v in asdict(self.safety).items()
            },
            "report_dir": self.report_dir,
            "default_timeout": self.default_timeout,
        }


EXAMPLE_YAML = """\
# AEGIS configuration. Copy to ./aegis.yaml and edit.
ollama:
  host: "http://localhost:11434"
  model: "gemma4:31b-cloud"     # primary reasoning model
  fallback_model: "gemma4:latest"
  timeout_seconds: 90
  temperature: 0.1
  enabled: true                 # set false to force the heuristic engine

safety:
  authorized: false             # MUST be true (or use --authorized) for non-local targets
  max_concurrency: 250
  max_duration_seconds: 600
  max_total_requests: 200000
  allowlist: []                 # e.g. ["api.staging.mycorp.com"]
  blocklist: []

report_dir: "aegis_reports"
default_timeout: 15.0
"""
