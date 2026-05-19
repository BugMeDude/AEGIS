"""Configuration loading and the responsible-use safety policy.

Precedence (lowest -> highest): built-in defaults < YAML file < environment
variables (``AEGIS_*``) < explicit CLI flags (applied by the caller).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .models import AuthLevel, ProxyConfig, TLSFingerprint

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

    v3 introduces progressive authorization tiers:
      - education (default): current capability — bounded payloads, no pivot,
        no exfil, no persistence
      - research: extended — WAF bypass, multi-stage chains, OOB callbacks
      - expert: full capability — all scanners, pivot, exfil validation

    AEGIS will only generate sustained load against a target the operator has
    explicitly affirmed they are authorised to test. Caps stop an accidental
    typo from turning a load test into a denial-of-service event.
    """

    authorized: bool = False
    # Progressive authorization tier (education | research | expert)
    auth_level: str = "education"
    # Lab mode: isolated, fully-authorised environment. Waives the
    # authorization prompt AND all load caps -> full capability, zero
    # friction. Default False so a fresh public clone stays safe.
    lab_mode: bool = False
    max_concurrency: int = 250
    max_duration_seconds: int = 600
    max_total_requests: int = 200_000
    # Hosts always allowed without the authorization affirmation (your own lab).
    local_allow: tuple[str, ...] = ("localhost", "127.0.0.1", "::1", "0.0.0.0")
    # If non-empty, ONLY these hosts (plus local_allow) may be targeted.
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] = ()
    # Digital watermarking: every report embeds operator identity
    operator: str = ""
    organization: str = ""
    # Attack budget (applied at auth_level tiers)
    budget_max_injection_points: int = 50
    budget_max_data_kb: int = 100
    budget_max_attack_seconds: int = 3600
    budget_allow_pivot: bool = False
    budget_allow_exfil: bool = False


@dataclass(slots=True)
class OllamaConfig:
    host: str = "http://localhost:11434"
    model: str = "gemma4:31b-cloud"
    fallback_model: str = "gemma4:latest"
    timeout_seconds: float = 90.0
    temperature: float = 0.1
    enabled: bool = True


@dataclass(slots=True)
class OpenAIConfig:
    api_key: str = ""
    model: str = "gpt-4o"
    org_id: str = ""
    timeout_seconds: float = 60.0
    temperature: float = 0.1
    enabled: bool = False


@dataclass(slots=True)
class AnthropicConfig:
    api_key: str = ""
    model: str = "claude-3-5-sonnet-20241022"
    timeout_seconds: float = 60.0
    temperature: float = 0.1
    enabled: bool = False


@dataclass(slots=True)
class AIProviderConfig:
    """Multi-provider AI configuration."""
    primary: str = "ollama"  # ollama | openai | anthropic
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    rag_enabled: bool = False
    rag_collection: str = "aegis_knowledge"
    agentic_enabled: bool = False


@dataclass(slots=True)
class AegisConfig:
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    ai: AIProviderConfig = field(default_factory=AIProviderConfig)
    safety: SafetyPolicy = field(default_factory=SafetyPolicy)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    tls: TLSFingerprint = field(default_factory=TLSFingerprint)
    report_dir: str = "aegis_reports"
    default_timeout: float = 15.0

    def __post_init__(self) -> None:
        # Single source of truth: the legacy ``cfg.ollama`` and the v3
        # ``cfg.ai.ollama`` are the SAME object. Disabling either one
        # (tests' ``cfg.ollama.enabled=False``, ``--no-ai`` setting
        # ``cfg.ai.ollama.enabled=False``, or ``AEGIS_NO_AI``) therefore
        # disables the router and preserves offline determinism.
        self.ai.ollama = self.ollama

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
        if "ai" in data and isinstance(data["ai"], dict):
            ai_cfg = data["ai"]
            if "ollama" in ai_cfg and isinstance(ai_cfg["ollama"], dict):
                for k, v in ai_cfg["ollama"].items():
                    if hasattr(cfg.ai.ollama, k):
                        setattr(cfg.ai.ollama, k, v)
            if "openai" in ai_cfg and isinstance(ai_cfg["openai"], dict):
                for k, v in ai_cfg["openai"].items():
                    if hasattr(cfg.ai.openai, k):
                        setattr(cfg.ai.openai, k, v)
            if "anthropic" in ai_cfg and isinstance(ai_cfg["anthropic"], dict):
                for k, v in ai_cfg["anthropic"].items():
                    if hasattr(cfg.ai.anthropic, k):
                        setattr(cfg.ai.anthropic, k, v)
            for k in ("primary", "rag_enabled", "agentic_enabled", "rag_collection"):
                if k in ai_cfg:
                    setattr(cfg.ai, k, ai_cfg[k])
        if "safety" in data and isinstance(data["safety"], dict):
            for k, v in data["safety"].items():
                if hasattr(cfg.safety, k):
                    setattr(cfg.safety, k, tuple(v) if isinstance(v, list) else v)
        if "proxy" in data and isinstance(data["proxy"], dict):
            for k, v in data["proxy"].items():
                if hasattr(cfg.proxy, k):
                    setattr(cfg.proxy, k, v)
        if "tls" in data and isinstance(data["tls"], dict):
            for k, v in data["tls"].items():
                if hasattr(cfg.tls, k):
                    setattr(cfg.tls, k, v)
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
            self.ai.ollama.enabled = False
        if env.get("AEGIS_AUTHORIZED") in ("1", "true", "yes"):
            self.safety.authorized = True
        if env.get("AEGIS_LAB_MODE") in ("1", "true", "yes"):
            self.safety.lab_mode = True
            self.safety.authorized = True
        if v := env.get("AEGIS_AUTH_LEVEL"):
            self.safety.auth_level = v
        if v := env.get("OPENAI_API_KEY"):
            self.ai.openai.api_key = v
            self.ai.openai.enabled = bool(v)
        if v := env.get("ANTHROPIC_API_KEY"):
            self.ai.anthropic.api_key = v
            self.ai.anthropic.enabled = bool(v)
        if env.get("AEGIS_RAG") in ("1", "true", "yes"):
            self.ai.rag_enabled = True
        if env.get("AEGIS_AGENTIC") in ("1", "true", "yes"):
            self.ai.agentic_enabled = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ollama": asdict(self.ollama),
            "ai": {
                "primary": self.ai.primary,
                "rag_enabled": self.ai.rag_enabled,
                "agentic_enabled": self.ai.agentic_enabled,
                "ollama": asdict(self.ai.ollama),
                "openai": {k: v for k, v in asdict(self.ai.openai).items()
                           if k != "api_key" or not v},
                "anthropic": {k: v for k, v in asdict(self.ai.anthropic).items()
                              if k != "api_key" or not v},
            },
            "safety": {
                k: (list(v) if isinstance(v, tuple) else v)
                for k, v in asdict(self.safety).items()
            },
            "proxy": asdict(self.proxy),
            "tls": asdict(self.tls),
            "report_dir": self.report_dir,
            "default_timeout": self.default_timeout,
        }


EXAMPLE_YAML = """\
# AEGIS v3 configuration. Copy to ./aegis.yaml and edit.

# ── AI Providers ──────────────────────────────────────────────────────
# AEGIS v3 supports multiple AI providers: ollama (default), openai, anthropic.
# Set primary to select which one is used for reasoning tasks.
ai:
  primary: "ollama"             # ollama | openai | anthropic
  rag_enabled: false            # enable RAG knowledge base (chromadb)
  agentic_enabled: false         # enable agentic attack planning loop
  ollama:
    host: "http://localhost:11434"
    model: "gemma4:31b-cloud"
    fallback_model: "gemma4:latest"
    timeout_seconds: 90
    temperature: 0.1
    enabled: true
  openai:
    api_key: ""                 # or set OPENAI_API_KEY env var
    model: "gpt-4o"
    timeout_seconds: 60
    enabled: false
  anthropic:
    api_key: ""                 # or set ANTHROPIC_API_KEY env var
    model: "claude-3-5-sonnet-20241022"
    timeout_seconds: 60
    enabled: false

# ── Safety Policy ────────────────────────────────────────────────────
# Progressive authorization tiers: education | research | expert
#   education (default): bounded payloads, no pivot, no exfil
#   research: WAF bypass, multi-stage chains, OOB callbacks
#   expert: full capability, all scanners, pivot, exfil validation
safety:
  authorized: false             # true (or --authorized) for non-local targets
  auth_level: "education"       # education | research | expert
  operator: ""                  # your name (embedded in report watermark)
  organization: ""              # your org (embedded in report watermark)
  max_concurrency: 250
  max_duration_seconds: 600
  max_total_requests: 200000
  allowlist: []                 # e.g. ["api.staging.mycorp.com"]
  blocklist: []

# ── Transport ─────────────────────────────────────────────────────────
proxy:
  http: ""                      # http://proxy:port
  https: ""                     # https://proxy:port
  socks5: ""                    # socks5://proxy:port
  tor: false                    # route through Tor (requires stem)
  chain: []                     # multi-hop proxy chain

tls:
  randomize: false              # randomize JA3/JA3S fingerprint
  impersonate: ""               # chrome | firefox | safari | ios | android

report_dir: "aegis_reports"
default_timeout: 15.0
"""
