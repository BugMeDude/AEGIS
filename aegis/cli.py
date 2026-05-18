"""AEGIS command-line interface (Typer + Rich).

Commands
  aegis doctor                 environment & Ollama health check
  aegis run      <input>       run a load+security test (you set the plan)
  aegis autopilot <input>      fully automated: AI plans, runs, analyses
  aegis ai       "<sentence>"  natural-language driven test
  aegis plan     <input>       show the AI-proposed plan only (no traffic)
  aegis report   <file.json>   re-render a saved JSON report
  aegis init                   write an example aegis.yaml
  aegis gui                    launch the desktop GUI
  aegis version
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
        f"[bold cyan]🛡  {__app_name__}[/]  [dim]v{__version__}[/]\n"
        f"[dim]{__tagline__}[/]\n"
        f"[bold yellow]{EDU_CAPTION}[/]",
        border_style="cyan"))


def _read_input(value: str) -> str:
    """Accept a literal string, a file path, or '-' for stdin."""
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
        cfg.ollama.enabled = False
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
        for col in ("Severity", "Type", "Endpoint", "Remediation"):
            vt.add_column(col, overflow="fold")
        for v in report.vulnerabilities:
            st = _SEV_STYLE.get(v.severity.value, "white")
            vt.add_row(f"[{st}]{v.severity.value}[/]", v.type,
                       v.endpoint, v.remediation)
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
             save, formats, offensive=False, nlp_query=None) -> int:
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
                                  on_event=emit)
            prog.update(tid, completed=100)
    except SafetyError as e:
        con.print(Panel(str(e), title="⛔ Refused (responsible-use policy)",
                        border_style="red"))
        return 3
    except Exception as e:  # pragma: no cover - surfaced to operator
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


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
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
    """Check the environment, Ollama connectivity and the active policy."""
    _banner()
    cfg = AegisConfig.load(config)
    orch = Orchestrator(cfg)
    t = Table(title="Environment", header_style="bold cyan")
    t.add_column("Check")
    t.add_column("Status")
    t.add_row("Python", sys.version.split()[0])
    try:
        import httpx  # noqa
        t.add_row("httpx", "[green]ok[/]")
    except Exception:
        t.add_row("httpx", "[red]missing[/]")

    health = orch.brain.client.health()
    if health.get("ok"):
        t.add_row("Ollama", f"[green]ok[/] @ {health['host']}")
        t.add_row("Model", f"[green]{health['model']}[/]")
        t.add_row("AI mode", "[green]LLM reasoning[/]")
    else:
        t.add_row("Ollama", f"[yellow]unavailable[/] ({health.get('reason','')})")
        t.add_row("AI mode", "[yellow]heuristic fallback (still fully functional)[/]")
    pol = cfg.safety
    if pol.lab_mode:
        t.add_row("Mode", "[bold magenta]LAB — full capability, no caps, "
                  "no auth prompt[/]")
        t.add_row("Caps", "[magenta]disabled (lab mode)[/]")
    else:
        t.add_row("Authorized", "[green]yes[/]" if pol.authorized else
                  "[yellow]no (non-local targets require --authorized/--lab)[/]")
        t.add_row("Caps", f"conc≤{pol.max_concurrency} · "
                  f"dur≤{pol.max_duration_seconds}s · "
                  f"reqs≤{pol.max_total_requests}")
    t.add_row("Edition", "Offensive + Defensive · Education & Research")
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
    input_type: str = typer.Option("auto", "--type", "-t",
                                    help="auto|curl|postman|openapi|har|url"),
    concurrency: int = typer.Option(10, "--concurrency", "-n"),
    duration: int = typer.Option(0, "--duration", "-d",
                                 help="Seconds (>0 enables duration mode)."),
    requests: int = typer.Option(100, "--requests", "-r",
                                 help="Total requests (count mode)."),
    rps: float = typer.Option(0.0, "--rps", help="Target requests/sec (0=max)."),
    ramp: int = typer.Option(0, "--ramp", help="Ramp-up seconds."),
    timeout: float = typer.Option(15.0, "--timeout"),
    ai_plan: bool = typer.Option(False, "--ai-plan",
                                 help="Let the AI design the plan instead."),
    offensive: bool = typer.Option(False, "--offensive", "-O",
                                   help="Add an active (offensive) DAST scan — "
                                        "education / authorised research only."),
    goal: str = typer.Option("", "--goal", "-g"),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized",
                                    help="Affirm you are authorised to test."),
    lab: bool = typer.Option(False, "--lab",
                             help="Authorised-lab mode: no auth prompt, no "
                                  "caps, full capability."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Force heuristic engine."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Run a load + security test with a plan you control."""
    _banner()
    cfg = _load_cfg(config, no_ai, authorized, lab)
    orch = Orchestrator(cfg)
    from .models import TestPlan
    user_plan = None if ai_plan else TestPlan(
        concurrency=concurrency, duration_seconds=duration,
        total_requests=requests, target_rps=rps, ramp_up_seconds=ramp,
        timeout_seconds=timeout, source="user",
        rationale="Operator-specified plan.")
    code = _execute(orch, raw=_read_input(input), input_type=input_type,
                    plan=user_plan, goal=goal, ai_plan=ai_plan,
                    offensive=offensive, save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def autopilot(
    input: str = typer.Argument(..., help="cURL / file / URL / Postman / OpenAPI"),
    input_type: str = typer.Option("auto", "--type", "-t"),
    offensive: bool = typer.Option(False, "--offensive", "-O",
                                   help="Add an active (offensive) DAST scan — "
                                        "education / authorised research only."),
    goal: str = typer.Option("", "--goal", "-g",
                             help="e.g. 'soak test', 'stress test', 'baseline'."),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab",
                             help="Authorised-lab mode: no auth prompt, no "
                                  "caps, full capability."),
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
                    offensive=offensive, save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def ai(
    query: str = typer.Argument(..., help="Plain-English test request."),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab",
                             help="Authorised-lab mode: no auth prompt, no "
                                  "caps, full capability."),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Natural language: aegis ai "stress https://x for 30s, 50 concurrent"."""
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
    requests: int = typer.Option(20, "--requests", "-r",
                                 help="Light baseline load before the scan."),
    concurrency: int = typer.Option(5, "--concurrency", "-n"),
    save: bool = typer.Option(True, "--save/--no-save"),
    formats: str = typer.Option("json,html,md", "--formats"),
    authorized: bool = typer.Option(False, "--authorized"),
    lab: bool = typer.Option(False, "--lab",
                             help="Authorised-lab mode: no auth prompt, no "
                                  "caps, full capability."),
    no_ai: bool = typer.Option(False, "--no-ai"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Offensive + defensive vulnerability scan (active DAST).

    Education / authorised security research only. Sends a small, curated set
    of injection-class test payloads (SQLi, XSS, traversal, command/template
    injection, open redirect, header auth-bypass) into discovered parameters,
    classifies the responses, and reports findings with remediation.
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
                    save=save, formats=formats)
    raise typer.Exit(code)


@app.command()
def report(
    file: str = typer.Argument(..., help="A previously saved aegis_report_*.json"),
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


def _report_from_dict(data: dict) -> RunReport:
    """Reconstruct just enough of a RunReport for re-rendering."""
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
    """Console-script entry point (see pyproject ``[project.scripts]``)."""
    app()


if __name__ == "__main__":
    main()
