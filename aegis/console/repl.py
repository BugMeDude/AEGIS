"""Interactive REPL console for AEGIS v3.

Provides a real-time shell with commands:
  - scan, inject, recon, pivot, exfil
  - session save/load/list
  - payload generate/mutate
  - campaign status
  - AI strategist guidance
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from .. import EDU_CAPTION, __app_name__, __version__
from ..ai import AIBrain, ModelRouter, AttackStrategist, PayloadEngine
from ..config import AegisConfig
from ..models import (
    Campaign, CampaignPhase, RequestSpec, TestPlan, VulnerabilityV3,
    Severity,
)
from ..offense import OffensiveScanner, active_scan
from ..orchestrator import Orchestrator
from ..recon import Fingerprinter, DiscoveryEngine, SchemaExtractor
from ..session import SessionManager

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.styles import Style as PTStyle
    _HAS_PROMPT = True
except ImportError:
    _HAS_PROMPT = False


class AegisREPL:
    """Interactive REPL for AEGIS v3 operations."""

    def __init__(self, config: AegisConfig | None = None) -> None:
        self.cfg = config or AegisConfig.load()
        self.orch = Orchestrator(self.cfg)
        self.brain = self.orch.brain
        self.router = self.brain.router
        self.strategist = self.brain.strategist
        self.payload_engine = self.brain.payload_engine
        self.recon_fp = Fingerprinter()
        self.recon_disc = DiscoveryEngine()
        self.recon_schema = SchemaExtractor()
        self.sessions = SessionManager()
        self.campaign: Campaign | None = None
        self._running = True

    def _banner(self) -> None:
        print(f"\n{'='*60}")
        print(f"  {__app_name__} v{__version__} — Interactive REPL")
        print(f"  {EDU_CAPTION}")
        print(f"{'='*60}")
        print("  Commands: scan, recon, inject, payload, session, campaign,")
        print("            strategist, config, help, exit")
        print(f"{'='*60}\n")

    def _cmd_help(self, args: list[str]) -> None:
        help_text = """
Available commands:
  campaign new <target> [--goal <goal>]  Start a new campaign
  campaign status                       Show campaign state
  campaign next                          Advance to next phase
  campaign list                          List saved sessions

  recon fingerprint <url>               Fingerprint target technology
  recon endpoints <base_url>            Discover endpoints
  recon schema <base_url>               Extract API schema
  recon params <url>                    Discover hidden params

  scan <url> [--offensive]              Run security scan
  inject <url> <param> <payload>        Single injection test
  payload generate <class>              Generate AI payloads
  payload mutate <payload>             Mutate payload for WAF bypass

  strategist plan <target> <goal>       AI attack plan
  strategist vectors                    AI-selected attack vectors

  session save [path]                   Save session
  session load <path>                   Load session
  session list                          List saved sessions

  config show                           Show current config
  config set <key> <value>             Set config value

  exit, quit                            Exit REPL
"""
        print(help_text)

    def _cmd_campaign(self, args: list[str]) -> None:
        if not args:
            print("Usage: campaign new|status|next|list [args]")
            return

        sub = args[0].lower()
        if sub == "new" and len(args) >= 2:
            target = args[1]
            goal = ""
            if "--goal" in args:
                gi = args.index("--goal")
                if gi + 1 < len(args):
                    goal = args[gi + 1]
            self.campaign = self.strategist.plan_campaign(
                target=target, goal=goal,
                auth_level=self.cfg.safety.auth_level,
            )
            print(f"Campaign created: {self.campaign.name}")
            print(f"  Phase: {self.campaign.phase.value}")
            print(f"  Auth Level: {self.campaign.auth_level.value}")

        elif sub == "status":
            if not self.campaign:
                print("No active campaign. Start one with 'campaign new'.")
                return
            print(f"Campaign: {self.campaign.name}")
            print(f"  Target: {self.campaign.target}")
            print(f"  Phase: {self.campaign.phase.value}")
            print(f"  Goal: {self.campaign.goal}")
            print(f"  Findings: {len(self.campaign.findings)}")
            print(f"  Pivot targets: {len(self.campaign.pivot_targets)}")

        elif sub == "next":
            if not self.campaign:
                print("No active campaign.")
                return
            next_phase = self.strategist.next_phase(self.campaign)
            self.campaign.phase = next_phase
            print(f"Moving to phase: {next_phase.value}")

        elif sub == "list":
            sessions = self.sessions.list_sessions()
            if not sessions:
                print("No saved sessions.")
                return
            print(f"{'Path':40s} {'Created':20s} {'Target':30s} {'Phase':15s}")
            print("-" * 105)
            for s in sessions:
                print(f"{s['path'][:38]:40s} {s['created']:20s} "
                      f"{s['target'][:28]:30s} {s['phase']:15s}")

    def _cmd_recon(self, args: list[str]) -> None:
        if not args:
            print("Usage: recon fingerprint|endpoints|schema|params [args]")
            return

        sub = args[0].lower()
        if sub == "fingerprint" and len(args) >= 2:
            import httpx
            url = args[1]
            try:
                r = httpx.get(url, timeout=10.0, verify=False)
                result = self.recon_fp.fingerprint(
                    r.status_code, dict(r.headers), r.text
                )
                print(f"\nFingerprint for {url}:")
                print(f"  Server: {result.get('server', 'unknown')}")
                print(f"  WAF: {result.get('waf', 'none detected')}")
                print(f"  Framework: {result.get('framework', 'unknown')}")
                print(f"  CDN: {result.get('cdn', 'none')}")
                print(f"  Auth: {result.get('auth', 'none detected')}")
            except Exception as e:
                print(f"Error: {e}")

        elif sub == "endpoints" and len(args) >= 2:
            base = args[1]
            print(f"Discovering endpoints on {base}...")
            found = asyncio.run(self.recon_disc.discover_endpoints(base))
            if found:
                print(f"\nDiscovered {len(found)} endpoints:")
                for ep in found[:20]:
                    print(f"  {ep}")
            else:
                print("No endpoints discovered.")

        elif sub == "schema" and len(args) >= 2:
            base = args[1]
            print(f"Extracting schema from {base}...")
            oa = asyncio.run(self.recon_schema.extract_from_openapi(base))
            gql = asyncio.run(self.recon_schema.extract_from_graphql(base))
            if oa:
                print(f"OpenAPI spec found! Endpoints: {len(self.recon_schema.endpoints)}")
            elif gql:
                print(f"GraphQL schema found! Types: {len(gql.get('data',{}).get('__schema',{}).get('types',[]))}")
            else:
                print("No schema endpoints found.")

        elif sub == "params" and len(args) >= 2:
            url = args[1]
            print(f"Fuzzing for hidden params on {url}...")
            found = asyncio.run(self.recon_disc.discover_params(url))
            if found:
                print(f"Discovered {len(found)} params:")
                for p in found:
                    print(f"  {p}")
            else:
                print("No hidden params discovered.")

    def _cmd_scan(self, args: list[str]) -> None:
        if not args:
            print("Usage: scan <url> [--offensive]")
            return
        url = args[0]
        offensive = "--offensive" in args

        spec = RequestSpec(url=url).normalised()
        plan = TestPlan(concurrency=5, total_requests=20, timeout_seconds=15)

        print(f"Scanning {url}...")
        print(f"  Offensive: {offensive}")

        report = self.orch.run(
            [spec], plan=plan, offensive=offensive,
        )

        print(f"\nResults:")
        print(f"  Requests: {report.total_attempts} ("
              f"✓{report.total_successes} ✗{report.total_failures})")
        print(f"  Avg latency: {report.overall_avg_ms:.0f} ms")
        print(f"  Vulnerabilities: {len(report.vulnerabilities)}")

        for v in report.vulnerabilities:
            sev_style = {
                Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH",
                Severity.MEDIUM: "MED", Severity.LOW: "LOW",
            }.get(v.severity, "INFO")
            print(f"  [{sev_style}] {v.type} — {v.endpoint}")
            print(f"    {v.remediation}")

        if self.campaign:
            self.campaign.findings.extend(
                v3 for v3 in [
                    VulnerabilityV3(type=v.type, description=v.description,
                                    severity=v.severity, endpoint=v.endpoint,
                                    remediation=v.remediation, evidence=v.evidence,
                                    source=v.source)
                    for v in report.vulnerabilities
                ]
            )

    def _cmd_payload(self, args: list[str]) -> None:
        if not args:
            print("Usage: payload generate|mutate [args]")
            return

        sub = args[0].lower()
        if sub == "generate" and len(args) >= 2:
            vuln_class = args[1]
            payloads = self.payload_engine.generate_payloads(
                vuln_class=vuln_class, count=5
            )
            print(f"\nGenerated payloads for {vuln_class}:")
            for i, p in enumerate(payloads, 1):
                print(f"  {i}. {p.get('payload', 'N/A')}")
                print(f"     {p.get('description', '')}")

        elif sub == "mutate" and len(args) >= 2:
            payload = args[1]
            vuln_class = args[2] if len(args) > 2 else "sqli"
            mutated = self.payload_engine.mutate_payload(
                payload, vuln_class=vuln_class
            )
            if mutated:
                print(f"Original: {payload}")
                print(f"Mutated:  {mutated}")
            else:
                print("No mutation generated.")

    def _cmd_strategist(self, args: list[str]) -> None:
        if not args:
            print("Usage: strategist plan|vectors [args]")
            return

        sub = args[0].lower()
        if sub == "plan" and len(args) >= 2:
            target = args[1]
            goal = " ".join(args[2:]) if len(args) > 2 else "security assessment"
            self.campaign = self.strategist.plan_campaign(
                target=target, goal=goal,
                auth_level=self.cfg.safety.auth_level,
            )
            print(f"Strategist campaign plan:")
            print(f"  Name: {self.campaign.name}")
            print(f"  Phase: {self.campaign.phase.value}")
            print(f"  Auth Level: {self.campaign.auth_level.value}")
            print(f"\nUse 'campaign status' and 'campaign next' to proceed.")

        elif sub == "vectors":
            print("Selecting optimal attack vectors...")
            # This would use the strategist with recon data.

    def _cmd_session(self, args: list[str]) -> None:
        if not args:
            print("Usage: session save|load|list [path]")
            return

        sub = args[0].lower()
        if sub == "save":
            path = args[1] if len(args) > 1 else ""
            saved = self.sessions.save(self.campaign, path)
            print(f"Session saved: {saved}")

        elif sub == "load" and len(args) >= 2:
            loaded = self.sessions.load(args[1])
            if loaded:
                self.campaign = loaded
                print(f"Session loaded: {loaded.name}")
                print(f"  Target: {loaded.target}")
                print(f"  Phase: {loaded.phase.value}")
            else:
                print("Failed to load session.")

        elif sub == "list":
            sessions = self.sessions.list_sessions()
            if not sessions:
                print("No saved sessions.")
                return
            print(f"{'Path':40s} {'Created':20s} {'Target':30s}")
            print("-" * 90)
            for s in sessions:
                print(f"{s['path'][:38]:40s} {s['created']:20s} {s['target'][:28]:30s}")

    def _cmd_config(self, args: list[str]) -> None:
        if not args:
            print("Usage: config show|set <key> <value>")
            return

        sub = args[0].lower()
        if sub == "show":
            print(json.dumps(self.cfg.to_dict(), indent=2))
        elif sub == "set" and len(args) >= 3:
            key = args[1]
            value = " ".join(args[2:])
            setattr(self.cfg, key, value)
            print(f"Set {key} = {value}")

    def _cmd_inject(self, args: list[str]) -> None:
        if len(args) < 3:
            print("Usage: inject <url> <param> <payload>")
            return
        url, param = args[0], args[1]
        payload = " ".join(args[2:])

        import httpx
        from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

        def inject(u: str, k: str, v: str) -> str:
            p = urlparse(u)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            q[k] = v
            return urlunparse(p._replace(query=urlencode(q)))

        test_url = inject(url, param, payload)
        try:
            r = httpx.get(test_url, timeout=10.0, verify=False)
            print(f"Status: {r.status_code}")
            print(f"Body ({len(r.text)}b): {r.text[:500]}")
        except Exception as e:
            print(f"Error: {e}")

    def run(self) -> None:
        """Start the REPL main loop."""
        self._banner()

        if not _HAS_PROMPT:
            print("Note: prompt_toolkit not available. Using basic input.")
            self._run_basic()
            return

        history_file = str(Path.home() / ".aegis" / "repl_history")
        Path(history_file).parent.mkdir(parents=True, exist_ok=True)

        style = PTStyle.from_dict({
            "prompt": "ansicyan bold",
        })

        session = PromptSession(
            history=FileHistory(history_file),
            style=style,
        )

        while self._running:
            try:
                text = session.prompt("aegis> ", style=style)
                if not text.strip():
                    continue
                self._execute(text.strip())
            except (KeyboardInterrupt, EOFError):
                print("\nExiting REPL.")
                self._running = False
                break
            except Exception as e:
                print(f"Error: {e}")

    def _run_basic(self) -> None:
        """Basic input loop without prompt_toolkit."""
        while self._running:
            try:
                text = input("aegis> ")
                if not text.strip():
                    continue
                self._execute(text.strip())
            except (KeyboardInterrupt, EOFError):
                print("\nExiting REPL.")
                self._running = False
                break

    def _execute(self, text: str) -> None:
        """Parse and execute a REPL command."""
        parts = shlex.split(text)
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        handlers = {
            "help": self._cmd_help,
            "?": self._cmd_help,
            "campaign": self._cmd_campaign,
            "recon": self._cmd_recon,
            "scan": self._cmd_scan,
            "inject": self._cmd_inject,
            "payload": self._cmd_payload,
            "strategist": self._cmd_strategist,
            "session": self._cmd_session,
            "config": self._cmd_config,
            "exit": lambda a: setattr(self, '_running', False),
            "quit": lambda a: setattr(self, '_running', False),
        }

        handler = handlers.get(cmd)
        if handler:
            handler(args)
        else:
            print(f"Unknown command: {cmd}. Type 'help' for available commands.")


def run_repl(config: AegisConfig | None = None) -> None:
    """Launch the AEGIS REPL."""
    repl = AegisREPL(config)
    repl.run()
