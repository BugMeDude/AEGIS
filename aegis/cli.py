"""AEGIS v3 command-line interface (Typer + Rich).

v3 adds:
  aegis recon    <target>     target reconnaissance (fingerprint, discover, schema)
  aegis campaign <target>     autonomous attack campaign
  aegis repl                  interactive REPL console
  aegis payload <class>       AI payload generation
  aegis chain   <name>        execute an attack chain
  aegis navigator <report>    generate MITRE ATT&CK Navigator layer

v2 commands unchanged:
  aegis run, autopilot, ai, plan, scan, report, doctor, init, gui, version
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table

from . import EDU_CAPTION, EDU_NOTICE, __app_name__, __tagline__, __version__
from .config import EXAMPLE_YAML, AegisConfig
from .models import RunReport, Severity
from .orchestrator import Orchestrator
from .reporting import write_reports
from .reporting.attack_mapper import ATTACKMapper
from .safety import SafetyError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=f"{__app_name__} v{__version__} — {__tagline__}",
)
con = Console()

_SEV_STYLE = {
    "Critical": "bold white on red", "High": "bold red",
    "Medium": "yellow", "Low": "cyan", "Info": "dim",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _banner() -> None:
    con.print(Panel.fit(
        f"[bold cyan]🛡  {__app_name__} v{__version__}[/]\n"
        f"[dim]{__tagline__}[/]\n"
        f"[bold yellow]{EDU_CAPTION}[/]",
        border_style="cyan"))


def _read_input(value: str) -> str:
    if value == "-":
        return sys.stdin.read()
    p = Path(value)
    if p.is_file():
        return p.read_text(encoding="utf-8")
    return value


def _load_cfg(config: str | None, no_ai: bool, authorized: bool,
              lab: bool = False) -> AegisConfig:
    cfg = AegisConfig.load(config)
    if no_ai:
        cfg.ai.ollama.enabled = False
        cfg.ai.primary = "ollama"
    if authorized:
        cfg.safety.authorized = True
    if lab:
        cfg.safety.lab_mode = True
        cfg.safety.authorized = True
    return cfg


def _progress_emitter(progress: Progress, task_id):
    def emit(event: str, data: dict) -> None:
        if event == "phase":
            progress.update(task_id, description=f"[cyan]{data['name'].title()}…")
        elif event == "progress":
            progress.update(task_id, completed=min(99.0, data.get("percent", 0)))
        elif event == "safety" and data.get("notes"):
            con.print(f"[yellow]⚠ safety clamp:[/] {', '.join(data['notes'])}")
        elif event == "plan":
            p = data["plan"]
            con.print(f"[dim]plan:[/] {p['mode']} · conc={p['concurrency']} · "
                      f"{'dur=' + str(p['duration_seconds']) + 's' if p['mode']=='duration' else 'n=' + str(p['total_requests'])}"
                      f" · [italic]{p['rationale']}[/]")
    return emit


def _render_report(report: RunReport) -> None:
    d = report.to_dict()
    s = d["summary"]
    ins = report.insight
    grade_color = {"A": "green", "B": "green", "C": "yellow",
                   "D": "red", "F": "bold red"}.get(ins.grade, "white")

    con.print()
    con.print(Panel(
        f"[{grade_color}]GRADE {ins.grade or '?'}[/]   "
        f"requests [bold]{s['total_attempts']}[/]  "
        f"(✓{s['total_successes']} ✗{s['total_failures']}, "
        f"[bold]{s['success_rate']}%[/] ok)\n"
        f"avg [bold]{s['overall_avg_ms']} ms[/]  ·  "
        f"throughput [bold]{s['throughput_rps']} rps[/]  ·  "
        f"engine [italic]{ins.engine}[/]",
        title="Result", border_style=grade_color))

    et = Table(title="Endpoints", expand=True, header_style="bold cyan")
    for col in ("Method", "URL", "Att", "OK%", "avg", "p95", "p99", "max"):
        et.add_column(col, overflow="fold")
    for e in report.endpoints:
        et.add_row(e.method, e.url, str(e.attempts), f"{e.success_rate:.0f}",
                   f"{e.avg_ms:.0f}", f"{e.p95:.0f}", f"{e.p99:.0f}",
                   f"{e.max_ms:.0f}")
    con.print(et)

    if report.vulnerabilities:
        vt = Table(title=f"Security findings ({len(report.vulnerabilities)})",
                   expand=True, header_style="bold red")
        for col in ("Severity", "Type", "Endpoint", "Remediation", "Source"):
            vt.add_column(col, overflow="fold")
        for v in report.vulnerabilities:
            st = _SEV_STYLE.get(v.severity.value, "white")
            vt.add_row(f"[{st}]{v.severity.value}[/]", v.type,
                       v.endpoint, v.remediation, v.source)
        con.print(vt)
    else:
        con.print("[green]✓ No security weaknesses detected.[/]")

    con.print(Panel(
        f"[bold]Summary.[/] {ins.summary}\n\n"
        f"[bold]Benchmark:[/] {ins.benchmark}\n"
        f"[bold]Optimization:[/] {ins.optimization}\n"
        f"[bold]Forecast:[/] {ins.prediction}",
        title="AI Insight", border_style="cyan"))
    if ins.assertions:
        con.print("[dim]Suggested assertions:[/] " +
                  " · ".join(f"[cyan]{a}[/]" for a in ins.assertions))


def _execute(orch: Orchestrator, *, raw, input_type, plan, goal, ai_plan,
             save, formats, offensive=False, nlp_query=None,
             enable_ai_payloads=False) -> int:
    if offensive:
        con.print(f"[yellow]⚔  Offensive active-scan enabled — {EDU_CAPTION}[/]")
    try:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TimeElapsedColumn(),
                      console=con, transient=True) as prog:
            tid = prog.add_task("[cyan]Starting…", total=100)
            emit = _progress_emitter(prog, tid)
            if nlp_query is not None:
                report = orch.from_nlp(nlp_query, on_event=emit)
            else:
                specs = orch.parse(raw, input_type=input_type)
                if not specs:
                    con.print("[bold red]✗ No requests parsed from input.[/]")
                    return 2
                report = orch.run(specs, plan=plan, goal=goal,
                                  ai_plan=ai_plan, offensive=offensive,
                                  enable_ai_payloads=enable_ai_payloads,
                                  on_event=emit)
            prog.update(tid, completed=100)
    except SafetyError as e:
        con.print(Panel(str(e), title="⛔ Refused (responsible-use policy)",
                        border_style="red"))
        return 3
    except Exception as e:
        con.print(f"[bold red]✗ {type(e).__name__}:[/] {e}")
        return 1

    _render_report(report)
    if save:
        written = write_reports(report, orch.config.report_dir,
                                [f.strip() for f in formats.split(",")])
        con.print("\n[green]Reports saved:[/]")
        for fmt, path in written.items():
            con.print(f"  [cyan]{fmt:>4}[/] → {path}")
    high = report.highest_severity
    return 4 if high in (Severity.CRITICAL, Severity.HIGH) else 0


# =================================================================== #
# v2 COMMANDS (unchanged)
# =================================================================== #

@app.command()
def version() -> None:
    """Print version and exit."""
    con.print(f"{__app_name__} {__version__}")


@app.command()
def init(
    path: str = typer.Option("aegis.yaml", help="Where to write the config."),
) -> None:
    """Write a commented example configuration file."""
    p = Path(path)
    if p.exists():
        con.print(f"[yellow]{p} already exists — not overwriting.[/]")
        raise typer.Exit(1)
    p.write_text(EXAMPLE_YAML, encoding="utf-8")
    con.print(f"[green]✓ wrote {p}[/]")


@app.command()
def doctor(
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Check the environment, AI providers and the active policy."""
    _banner()
    cfg = AegisConfig.load(config)
    orch = Orchestrator(cfg)
    t = Table(title="Environment", header_style="bold cyan")
    t.add_column("Check")
    t.add_column("Status")
    t.add_row("Python", sys.version.split()[0])

    ai_mode = cfg.ai.primary
    t.add_row("AI Provider", f"[green]{ai_mode}[/]")

    available = orch.brain.router.available_providers()
    if available:
        t.add_row("AI Providers", f"[green]{', '.join(available)}[/]")
        best = orch.brain.router.best_provider()
        if best and hasattr(best, 'active_model'):
            t.add_row("Active Model", f"[green]{best.active_model}[/]")
        t.add_row("Agentic AI", "[green]enabled[/]" if cfg.ai.agentic_enabled
                  else "[yellow]disabled (set ai.agentic_enabled: true)[/]")
        t.add_row("RAG Knowledge", "[green]enabled[/]" if cfg.ai.rag_enabled
                  else "[yellow]disabled (set ai.rag_enabled: true)[/]")
    else:
        t.add_row("AI Status", "[yellow]No providers available — heuristic mode[/]")

    pol = cfg.safety
    if pol.lab_mode:
        t.add_row("Mode", "[bold magenta]LAB — full capability, no caps, "
                  "no auth prompt[/]")
        t.add_row("Auth Level", f"[magenta]{pol.auth_level}[/]")
        t.add_row("Caps", "[magenta]disabled (lab mode)[/]")
    else:
        t.add_row("Authorized", "[green]yes[/]" if pol.authorized else
                  "[yellow]no (non-local targets require --authorized/--lab)[/]")
        t.add_row("Auth Level", f"[cyan]{pol.auth_level}[/]")
        t.add_row("Caps", f"conc≤{pol.max_concurrency} · "
                  f"dur≤{pol.max_duration_seconds}s · "
                  f"reqs≤{pol.max_total_requests}")
    t.add_row("Edition", "v3 Offensive + Defensive · Red Team · Education & Research")
    con.print(t)
    con.print(Panel(EDU_NOTICE, title="⚠ Responsible-use & education notice",
                     border_style="yellow"))


@app.command()
def plan(
    input: str = typer.Argument(..., help="cURL / file / URL / Postman / OpenAPI"),
    input_type: str = typer.Option("auto", "--type", "-t"),
    goal: str = typer.Option("", "--goal", "-g", help="What you want to learn."),
    config: str = typer.Option(None, "--config", "-c"),
    no_ai: bool = typer.Option(False, "--no-ai"),
) -> None:
    """Show the AI-proposed test plan WITHOUT sending any traffic."""
    cfg = _load_cfg(config, no_ai, authorized=False)
    orch = Orchestrator(cfg)
    specs = orch.parse(_read_input(input), input_type=input_type)
    if not specs:
        con.print("[red]No requests parsed.[/]")
        raise typer.Exit(2)
    p = orch.brain.plan(specs, goal, cfg.safety)
    con.print(Panel(
        f"[bold]{p.mode().upper()}[/] model · source [italic]{p.source}[/]\n"
        f"concurrency [bold]{p.concurrency}[/]\n"
        + (f"duration [bold]{p.duration_seconds}s[/]\n"
           if p.mode() == "duration"
           else f"total requests [bold]{p.total_requests}[/]\n")
        + (f"target rps [bold]{p.target_rps}[/]\n" if p.target_rps else "")
        + (f"ramp-up [bold]{p.ramp_up_seconds}s[/]\n" if p.ramp_up_seconds else "")
        + f"\n[dim]{p.rationale}[/]",
        title=f"Proposed plan for {len(specs)} request(s)",
        border_style="cyan"))


@app.command()
def run(
    input: str = typer.Argument(..., help="cURL / file / URL / Postman / OpenAPI"),
    input_type: str = typer.Option("auto", "--type", "-t"),
    concurrency: int = typer.Option(10, "--concurrency", "-n"),
    duration: int = typer.Option(0, "--duration", "-d"),
    requests: int = typer.Option(100, "--requests", "-r"),
    rps: float = typer.Option(0.0, "--rps"),
    ramp: int = typer.Option(0, "--ramp"),
    timeout: float = typer.Option(15.0, "--timeout"),
    http2: bool = typer.Option(False, "--http2",
                               help="Negotiate HTTP/2 (ALPN h2) if offered."),
    ai_plan: bool = typer.Option(False, "--ai-plan"),
    offensive: bool = typer.Option(False, "--offensive", "-O"),
    ai_payloads: bool = typer.Option(False, "--ai-payloads",
                                      help="Use AI-generated payloads in scans."),
    goal: str = typer.Option("", "--goal", "-g"),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Run a load + security test with a plan you control (v3 enhanced)."""
    _banner()
    cfg = _load_cfg(config, no_ai, authorized, lab)
    orch = Orchestrator(cfg)
    from .models import TestPlan
    user_plan = None if ai_plan else TestPlan(
        concurrency=concurrency, duration_seconds=duration,
        total_requests=requests, target_rps=rps, ramp_up_seconds=ramp,
        timeout_seconds=timeout, http2=http2, source="user",
        rationale="Operator-specified plan.")
    code = _execute(orch, raw=_read_input(input), input_type=input_type,
                    plan=user_plan, goal=goal, ai_plan=ai_plan,
                    offensive=offensive, enable_ai_payloads=ai_payloads,
                    save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def autopilot(
    input: str = typer.Argument(..., help="cURL / file / URL / Postman / OpenAPI"),
    input_type: str = typer.Option("auto", "--type", "-t"),
    offensive: bool = typer.Option(False, "--offensive", "-O"),
    ai_payloads: bool = typer.Option(False, "--ai-payloads"),
    goal: str = typer.Option("", "--goal", "-g"),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Fully automated: the AI plans, runs, analyses and reports."""
    _banner()
    con.print("[cyan]🤖 Autopilot engaged — AI will design and run the test.[/]")
    cfg = _load_cfg(config, no_ai, authorized, lab)
    orch = Orchestrator(cfg)
    code = _execute(orch, raw=_read_input(input), input_type=input_type,
                    plan=None, goal=goal, ai_plan=True,
                    offensive=offensive, enable_ai_payloads=ai_payloads,
                    save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def ai(
    query: str = typer.Argument(..., help="Plain-English test request."),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Natural language: aegis ai 'stress https://x for 30s, 50 concurrent'."""
    _banner()
    cfg = _load_cfg(config, no_ai, authorized, lab)
    orch = Orchestrator(cfg)
    code = _execute(orch, raw="", input_type="auto", plan=None, goal="",
                    ai_plan=False, save=save, formats=formats,
                    nlp_query=query)
    raise typer.Exit(code)


@app.command()
def scan(
    input: str = typer.Argument(..., help="cURL / file / URL / Postman / OpenAPI"),
    input_type: str = typer.Option("auto", "--type", "-t"),
    requests: int = typer.Option(20, "--requests", "-r"),
    concurrency: int = typer.Option(5, "--concurrency", "-n"),
    ai_payloads: bool = typer.Option(False, "--ai-payloads",
                                      help="AI-driven payload generation."),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Offensive + defensive vulnerability scan with v3 enhanced scanners.

    Covers 15+ vulnerability classes: SQLi, XSS, SSTI, SSRF, XXE, traversal,
    command injection, NoSQLi, open redirect, header bypass, JWT, deserialization.
    """
    _banner()
    con.print(Panel(EDU_NOTICE, title="⚠ Responsible-use & education notice",
                    border_style="yellow"))
    cfg = _load_cfg(config, no_ai, authorized, lab)
    orch = Orchestrator(cfg)
    from .models import TestPlan
    plan = TestPlan(concurrency=concurrency, total_requests=requests,
                    timeout_seconds=cfg.default_timeout, source="user",
                    rationale="Light baseline before offensive scan.")
    code = _execute(orch, raw=_read_input(input), input_type=input_type,
                    plan=plan, goal="", ai_plan=False, offensive=True,
                    enable_ai_payloads=ai_payloads, save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def report(
    file: str = typer.Argument(..., help="A saved aegis_report_*.json"),
    formats: str = typer.Option("html,md", "--formats"),
    out: str = typer.Option("aegis_reports", "--out"),
) -> None:
    """Re-render a saved JSON report to HTML/Markdown/CSV."""
    data = json.loads(Path(file).read_text(encoding="utf-8"))
    rep = _report_from_dict(data)
    written = write_reports(rep, out, [f.strip() for f in formats.split(",")])
    for fmt, path in written.items():
        con.print(f"[green]{fmt}[/] → {path}")


@app.command()
def gui(config: str = typer.Option(None, "--config", "-c")) -> None:
    """Launch the AEGIS desktop application."""
    try:
        from .gui import launch
    except Exception as e:
        con.print(f"[red]GUI unavailable: {e}[/]")
        raise typer.Exit(1)
    launch(AegisConfig.load(config))


# =================================================================== #
# v3 NEW COMMANDS
# =================================================================== #

@app.command()
def recon(
    target: str = typer.Argument(..., help="Target URL to reconnoitre."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Full reconnaissance: fingerprint, discover, extract schema.

    Performs technology stack fingerprinting, API endpoint discovery,
    OpenAPI/GraphQL schema extraction, and hidden parameter fuzzing.
    """
    _banner()
    cfg = AegisConfig.load(config)
    orch = Orchestrator(cfg)

    con.print(f"[cyan]🔍 Reconnaissance against:[/] {target}\n")

    import asyncio

    async def do_recon():
        return await orch.run_recon(target)

    results = asyncio.run(do_recon())

    fp = results.get("fingerprint", {})
    t = Table(title="Technology Fingerprint", header_style="bold cyan")
    t.add_column("Property")
    t.add_column("Detected")
    for k, v in fp.items():
        if k != "all_headers" and v:
            t.add_row(k.replace("_", " ").title(), str(v))
    con.print(t)

    eps = results.get("endpoints", [])
    if eps:
        con.print(f"\n[green]Discovered {len(eps)} endpoint(s):[/]")
        for ep in eps[:15]:
            con.print(f"  {ep}")
    else:
        con.print("\n[yellow]No additional endpoints discovered.[/]")

    schema = results.get("schema")
    if schema:
        con.print(f"\n[green]API Schema:[/] {schema.get('type', 'unknown')}")

    params = results.get("params", [])
    if params:
        con.print(f"\n[green]Hidden params ({len(params)}):[/] {', '.join(params[:10])}")


@app.command()
def protocols(
    target: str = typer.Argument(..., help="Target URL or host:port."),
    timeout: float = typer.Option(8.0, "--timeout"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Test HTTP/2, WebSocket and gRPC support (Phase 4.2, observation only)."""
    _banner()
    orch = Orchestrator(AegisConfig.load(config))
    con.print(f"[cyan]🔌 Protocol probe:[/] {target}\n")
    r = orch.test_protocols(target, timeout=timeout)
    h = r["http2"]
    con.print(f"[bold]HTTP/2[/]  supported=[{'green' if h['http2_supported'] else 'yellow'}]"
              f"{h['http2_supported']}[/]  negotiated={h.get('negotiated') or '-'}  "
              f"status={h.get('status')}  {h.get('error') or ''}")
    w = r["websocket"]
    con.print(f"[bold]WebSocket[/]  connected=[{'green' if w['connected'] else 'yellow'}]"
              f"{w['connected']}[/]  probes={len(w.get('observations', []))}  "
              f"{w.get('error') or ''}")
    for o in w.get("observations", []):
        con.print(f"   · {o['probe']:<14} {o['ms']:>7.1f}ms  reply={o['reply']}")
    g = r["grpc"]
    con.print(f"[bold]gRPC[/]  grpcio={g.get('grpcio')}  method={g.get('method')}  "
              f"{('services=' + str(g.get('services'))) if g.get('services') else ''}"
              f"{('looks_like_grpc=' + str(g.get('looks_like_grpc'))) if 'looks_like_grpc' in g else ''}"
              f"  {g.get('error') or ''}")


@app.command()
def validate(
    input: str = typer.Argument(..., help="A saved aegis_report_*.json"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Bounded proof-of-impact for SQLi/XSS findings in a saved report.

    Phase 6.1. EXPERT auth tier + budget required. Confirms exploitability
    with a few probes; never enumerates or dumps data.
    """
    _banner()
    cfg = _load_cfg(config, True, authorized, lab)
    orch = Orchestrator(cfg)
    rep = _report_from_dict(json.loads(Path(input).read_text(encoding="utf-8")))
    con.print("[cyan]🧪 Proof-of-impact validation (bounded, no extraction)[/]\n")
    rows = orch.validate_findings(rep)
    if not rows:
        con.print("[yellow]No SQLi/XSS findings to validate.[/]")
        raise typer.Exit(0)
    t = Table(header_style="bold cyan")
    for c in ("Type", "Endpoint", "Confirmed", "Method", "Probes", "Notes"):
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(r["finding_type"], r["endpoint"],
                  "[green]YES[/]" if r["confirmed"] else "no",
                  r["method"] or "-", str(r["probes_used"]), r["notes"])
    con.print(t)


@app.command()
def assess(
    targets: list[str] = typer.Argument(..., help="Explicit authorised "
                                        "targets (URLs/host:port)."),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Scoped assessment of additional EXPLICITLY-supplied authorised targets.

    Phase 6.2 (safe form). Each target is independently re-authorised. No
    auto-pivot, no tunnelling, no lateral movement.
    """
    _banner()
    cfg = _load_cfg(config, True, authorized, lab)
    orch = Orchestrator(cfg)
    con.print(f"[cyan]🛰  Scoped assessment of {len(targets)} target(s)[/]\n")
    t = Table(header_style="bold cyan")
    for c in ("Target", "Authorised", "Status", "Server", "Note"):
        t.add_column(c, overflow="fold")
    for r in orch.assess_scope(list(targets)):
        fp = r.get("fingerprint", {})
        t.add_row(r["target"],
                  "[green]yes[/]" if r["authorised"] else "[red]no[/]",
                  str(r.get("status", "-")),
                  str(fp.get("server", "-")) if fp else "-",
                  r.get("error") or "ok")
    con.print(t)


@app.command()
def campaign(
    target: str = typer.Argument(..., help="Campaign target."),
    goal: str = typer.Option("security assessment", "--goal", "-g"),
    offensive: bool = typer.Option(True, "--offensive/--no-offensive"),
    ai_payloads: bool = typer.Option(False, "--ai-payloads"),
    chain: list[str] = typer.Option([], "--chain",
                                     help="Attack chains to run (sqli_to_auth, etc)"),
    save: bool = typer.Option(True, "--save/--no-save"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(True, "--lab"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Run a complete autonomous attack campaign against a target.

    Orchestrates: recon → fingerprint → enumerate → exploit → report.
    Supports AI-strategist-driven phase transitions.
    """
    _banner()
    cfg = _load_cfg(config, False, authorized, lab)
    orch = Orchestrator(cfg)

    con.print(Panel(f"🎯 Campaign target: {target}\n"
                     f"   Goal: {goal}\n"
                     f"   Auth Level: {cfg.safety.auth_level}\n"
                     f"   Attack chains: {', '.join(chain) or 'none'}",
                     title="Campaign Launch", border_style="red"))

    # Phase 1: Reconnaissance
    con.print("\n[cyan]Phase 1: Reconnaissance[/]")
    import asyncio
    recon_results = asyncio.run(orch.run_recon(target))

    fp = recon_results.get("fingerprint", {})
    con.print(f"  Server: {fp.get('server', 'unknown')}")
    con.print(f"  WAF: {fp.get('waf', 'none')}")
    con.print(f"  Framework: {fp.get('framework', 'unknown')}")

    # Phase 2: Parse + Scan
    con.print("\n[cyan]Phase 2: Scanning[/]")
    specs = orch.parse(target)
    if not specs:
        specs = [__import__('aegis.models', fromlist=['RequestSpec']).RequestSpec(url=target).normalised()]

    from .models import TestPlan
    plan = TestPlan(concurrency=10, total_requests=50, source="campaign",
                    rationale=f"Campaign: {goal}")

    report = orch.run(specs, plan=plan, goal=goal,
                      offensive=offensive, enable_ai_payloads=ai_payloads,
                      chain_names=chain, enable_chains=bool(chain))

    # Phase 3: Results
    _render_report(report)
    if save:
        written = write_reports(report, cfg.report_dir)
        con.print("\n[green]Reports saved:[/]")
        for fmt, path in written.items():
            con.print(f"  [cyan]{fmt:>4}[/] → {path}")

    # Generate MITRE Navigator layer
    if report.vulnerabilities:
        v3_findings = [
            __import__('aegis.models', fromlist=['VulnerabilityV3']).VulnerabilityV3(
                type=v.type, description=v.description, severity=v.severity,
                endpoint=v.endpoint, remediation=v.remediation,
                evidence=v.evidence, source=v.source
            )
            for v in report.vulnerabilities
        ]
        nav = ATTACKMapper.generate_navigator_layer(v3_findings)
        nav_path = Path(cfg.report_dir) / f"mitre_navigator_{report.started_at.replace(' ','_').replace(':','')}.json"
        nav_path.write_text(nav)
        con.print(f"\n[green]MITRE Navigator layer:[/] {nav_path}")


@app.command()
def repl(
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Launch the interactive AEGIS REPL console.

    Provides real-time commands for scanning, recon, injection,
    payload generation, session management, and campaign control.
    """
    try:
        from .console.repl import run_repl
        run_repl(AegisConfig.load(config))
    except ImportError as e:
        con.print(f"[red]REPL unavailable: {e}[/]")
        raise typer.Exit(1)


@app.command()
def payload(
    vuln_class: str = typer.Argument(..., help="sqli, xss, ssrf, cmdi, ssti, etc."),
    count: int = typer.Option(5, "--count", "-n"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Generate AI-crafted security test payloads."""
    cfg = AegisConfig.load(config)
    orch = Orchestrator(cfg)
    payloads = orch.payload_engine.generate_payloads(
        vuln_class=vuln_class, count=count
    )
    if not payloads:
        con.print("[yellow]No payloads generated. Check AI provider availability.[/]")
        return
    t = Table(title=f"AI Payloads — {vuln_class}", header_style="bold cyan")
    t.add_column("#")
    t.add_column("Payload")
    t.add_column("Description")
    for i, p in enumerate(payloads, 1):
        t.add_row(str(i), str(p.get("payload", ""))[:80],
                  str(p.get("description", ""))[:60])
    con.print(t)


@app.command()
def chain(
    name: str = typer.Argument(..., help="Attack chain name (sqli_to_auth, ssrf_to_cloud, xss_to_session)"),
    target: str = typer.Argument(..., help="Target URL"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Execute a pre-built multi-stage attack chain."""
    from .offense.chains import AttackChain
    from .models import RequestSpec

    cfg = AegisConfig.load(config)
    chain_exec = AttackChain.by_name(name)
    if not chain_exec.steps:
        available = AttackChain.list_chains()
        con.print(f"[red]Unknown chain: {name}. Available: {', '.join(available)}[/]")
        raise typer.Exit(1)

    spec = RequestSpec(url=target).normalised()
    con.print(f"[cyan]Executing attack chain:[/] {name}")
    con.print(f"[dim]Target:[/] {target}")
    con.print(f"[dim]Steps:[/] {len(chain_exec.steps)}\n")

    import asyncio
    result = asyncio.run(chain_exec.execute(spec))

    t = Table(title=f"Chain Result: {name}", header_style="bold cyan")
    t.add_column("Metric")
    t.add_column("Value")
    t.add_row("Success", "[green]✓[/]" if result.success else "[red]✗[/]")
    t.add_row("Steps completed", f"{result.steps_completed}/{result.total_steps}")
    t.add_row("Findings", str(len(result.findings)))
    con.print(t)

    if result.findings:
        ft = Table(header_style="bold red")
        ft.add_column("Type")
        ft.add_column("Severity")
        ft.add_column("Evidence")
        for f in result.findings:
            ft.add_row(f.type, f.severity.value, f.evidence[:60])
        con.print(ft)


@app.command()
def navigator(
    report_file: str = typer.Argument(..., help="AEGIS JSON report file."),
    out: str = typer.Option("mitre_layer.json", "--out", "-o"),
) -> None:
    """Generate a MITRE ATT&CK Navigator layer from a report."""
    data = json.loads(Path(report_file).read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        con.print("[yellow]No vulnerabilities found in report.[/]")
        return

    from .models import Severity as Sev, VulnerabilityV3
    findings = [
        VulnerabilityV3(
            type=v["type"], description=v.get("description", ""),
            severity=Sev(v["severity"]), endpoint=v.get("endpoint", ""),
            remediation=v.get("remediation", ""), evidence=v.get("evidence", ""),
            source=v.get("source", "heuristic"),
        )
        for v in vulns
    ]

    nav = ATTACKMapper.generate_navigator_layer(findings)
    Path(out).write_text(nav)
    con.print(f"[green]MITRE Navigator layer written:[/] {out}")


# =================================================================== #
# report re-constructor
# =================================================================== #
def _report_from_dict(data: dict) -> RunReport:
    from .models import AIInsight, EndpointStats, TestPlan
    rep = RunReport(started_at=data.get("started_at", ""))
    rep.finished_at = data.get("finished_at", "")
    rep.targets = data.get("targets", [])
    s = data.get("summary", {})
    rep.total_attempts = s.get("total_attempts", 0)
    rep.total_successes = s.get("total_successes", 0)
    rep.total_failures = s.get("total_failures", 0)
    rep.throughput_rps = s.get("throughput_rps", 0.0)
    pd = data.get("plan", {})
    rep.plan = TestPlan(concurrency=pd.get("concurrency", 0),
                        duration_seconds=pd.get("duration_seconds", 0),
                        total_requests=pd.get("total_requests", 0),
                        rationale=pd.get("rationale", ""))
    for e in data.get("endpoints", []):
        es = EndpointStats(url=e["url"], method=e["method"])
        es.attempts = e["attempts"]
        es.successes = e["successes"]
        es.failures = e["failures"]
        es.latencies = [e["avg_ms"]] * max(1, e["attempts"])
        es.status_codes = {int(k): v for k, v in e.get("status_codes", {}).items()}
        rep.endpoints.append(es)
    from .models import Severity, Vulnerability
    for v in data.get("vulnerabilities", []):
        rep.vulnerabilities.append(Vulnerability(
            v["type"], v["description"], Severity(v["severity"]),
            v.get("endpoint", ""), v.get("remediation", ""),
            v.get("evidence", ""), v.get("source", "heuristic")))
    i = data.get("insight", {})
    rep.insight = AIInsight(
        summary=i.get("summary", ""), benchmark=i.get("benchmark", ""),
        optimization=i.get("optimization", ""), prediction=i.get("prediction", ""),
        assertions=i.get("assertions", []), grade=i.get("grade", ""),
        engine=i.get("engine", "heuristic"))
    return rep


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
