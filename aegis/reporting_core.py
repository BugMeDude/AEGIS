"""Report writers: JSON, CSV, Markdown and a self-contained HTML dashboard."""

from __future__ import annotations

import csv
import html
import json
import time
from pathlib import Path

from . import EDU_CAPTION, EDU_NOTICE
from .models import RunReport

_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS Report &mdash; {started}</title>
<style>
:root{{--bg:#0c0f17;--card:#151a26;--ink:#e6edf3;--mut:#8b97a8;
--ok:#3fb950;--warn:#d29922;--bad:#f85149;--acc:#58a6ff}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 -apple-system,Segoe UI,
Roboto,Ubuntu,sans-serif;background:var(--bg);color:var(--ink)}}
.wrap{{max-width:1100px;margin:0 auto;padding:32px}}
h1{{margin:0;font-size:26px;letter-spacing:.5px}}
.sub{{color:var(--mut);margin:6px 0 26px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
gap:14px;margin-bottom:26px}}
.card{{background:var(--card);border:1px solid #232a3a;border-radius:12px;
padding:16px 18px}}
.card .k{{color:var(--mut);font-size:12px;text-transform:uppercase;
letter-spacing:.8px}}.card .v{{font-size:24px;font-weight:700;margin-top:6px}}
table{{width:100%;border-collapse:collapse;background:var(--card);
border-radius:12px;overflow:hidden;margin:10px 0 28px}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #232a3a;
font-size:13px}}th{{background:#1b2230;color:var(--mut);text-transform:uppercase;
font-size:11px;letter-spacing:.6px}}tr:last-child td{{border-bottom:0}}
.sev-Critical{{color:var(--bad);font-weight:700}}.sev-High{{color:#ff7b72}}
.sev-Medium{{color:var(--warn)}}.sev-Low{{color:#58a6ff}}.sev-Info{{color:var(--mut)}}
.grade{{font-size:46px;font-weight:800}}
.A{{color:var(--ok)}}.B{{color:#7ee787}}.C{{color:var(--warn)}}
.D{{color:#ff7b72}}.F{{color:var(--bad)}}
.box{{background:var(--card);border:1px solid #232a3a;border-radius:12px;
padding:18px 20px;margin-bottom:22px}}h2{{font-size:15px;color:var(--mut);
text-transform:uppercase;letter-spacing:1px;margin:26px 0 10px}}
.tag{{display:inline-block;background:#1b2230;color:var(--acc);padding:2px 8px;
border-radius:6px;font-size:12px}}.foot{{color:var(--mut);font-size:12px;
margin-top:30px;text-align:center}}
</style></head><body><div class="wrap">
<h1>&#128737; AEGIS Security &amp; Performance Report</h1>
<div class="sub">{targets} &middot; started {started} &middot; engine
<span class="tag">{engine}</span></div>
<div class="box" style="border-color:#5a4a12;background:#221c08;color:#f0c674">
<strong>{edu_caption}</strong><br><span style="color:#c9b884">{edu_notice}</span>
</div>
<div class="grid">
<div class="card"><div class="k">Grade</div>
<div class="grade {grade}">{grade}</div></div>
<div class="card"><div class="k">Requests</div><div class="v">{attempts}</div></div>
<div class="card"><div class="k">Success</div><div class="v">{success_rate}%</div></div>
<div class="card"><div class="k">Avg latency</div><div class="v">{avg} ms</div></div>
<div class="card"><div class="k">Throughput</div><div class="v">{rps} rps</div></div>
<div class="card"><div class="k">Top severity</div>
<div class="v sev-{sev}">{sev}</div></div>
</div>
<div class="box"><strong>Executive summary.</strong> {summary}<br><br>
<strong>Benchmark:</strong> {benchmark}<br>
<strong>Optimization:</strong> {optimization}<br>
<strong>Forecast:</strong> {prediction}</div>
<h2>Endpoints</h2>{ep_table}
<h2>Security findings ({nvuln})</h2>{vuln_table}
<h2>Suggested assertions</h2><div class="box">{assertions}</div>
<div class="foot">AEGIS v2.0.0 &mdash; Autonomous API Stress &amp; Security
Intelligence Platform. Authorised testing only.</div>
</div></body></html>"""


def _ep_table(report: RunReport) -> str:
    if not report.endpoints:
        return "<p>No endpoint data.</p>"
    rows = ["<table><tr><th>Method</th><th>URL</th><th>Att</th><th>OK%</th>"
            "<th>avg</th><th>p95</th><th>p99</th><th>max</th></tr>"]
    for e in report.endpoints:
        rows.append(
            f"<tr><td>{html.escape(e.method)}</td>"
            f"<td>{html.escape(e.url)}</td><td>{e.attempts}</td>"
            f"<td>{e.success_rate:.1f}</td><td>{e.avg_ms:.0f}</td>"
            f"<td>{e.p95:.0f}</td><td>{e.p99:.0f}</td>"
            f"<td>{e.max_ms:.0f}</td></tr>")
    return "".join(rows) + "</table>"


def _vuln_table(report: RunReport) -> str:
    if not report.vulnerabilities:
        return '<div class="box">No security weaknesses detected. &#9989;</div>'
    rows = ["<table><tr><th>Severity</th><th>Type</th><th>Endpoint</th>"
            "<th>Description</th><th>Remediation</th><th>Src</th></tr>"]
    for v in report.vulnerabilities:
        rows.append(
            f'<tr><td class="sev-{v.severity.value}">{v.severity.value}</td>'
            f"<td>{html.escape(v.type)}</td>"
            f"<td>{html.escape(v.endpoint)}</td>"
            f"<td>{html.escape(v.description)}</td>"
            f"<td>{html.escape(v.remediation)}</td>"
            f"<td>{v.source}</td></tr>")
    return "".join(rows) + "</table>"


def render_html(report: RunReport) -> str:
    d = report.to_dict()
    ins = report.insight
    return _HTML.format(
        started=html.escape(report.started_at),
        targets=html.escape(", ".join(report.targets) or "n/a"),
        engine=html.escape(ins.engine),
        edu_caption=html.escape(EDU_CAPTION),
        edu_notice=html.escape(EDU_NOTICE),
        grade=html.escape(ins.grade or "?"),
        attempts=d["summary"]["total_attempts"],
        success_rate=d["summary"]["success_rate"],
        avg=d["summary"]["overall_avg_ms"],
        rps=d["summary"]["throughput_rps"],
        sev=d["summary"]["highest_severity"],
        summary=html.escape(ins.summary or "n/a"),
        benchmark=html.escape(ins.benchmark or "n/a"),
        optimization=html.escape(ins.optimization or "n/a"),
        prediction=html.escape(ins.prediction or "n/a"),
        ep_table=_ep_table(report),
        vuln_table=_vuln_table(report),
        nvuln=len(report.vulnerabilities),
        assertions="<br>".join(html.escape(a) for a in ins.assertions) or "n/a",
    )


def render_markdown(report: RunReport) -> str:
    d = report.to_dict()
    s, ins = d["summary"], report.insight
    out = [
        f"# AEGIS Report — {report.started_at}",
        f"\n> **{EDU_CAPTION}**  ",
        f"> {EDU_NOTICE}\n",
        f"\n**Targets:** {', '.join(report.targets)}  ",
        f"**Engine:** `{ins.engine}`  **Grade:** **{ins.grade}**\n",
        "## Summary\n",
        f"- Requests: **{s['total_attempts']}** "
        f"(✓{s['total_successes']} / ✗{s['total_failures']}, "
        f"{s['success_rate']}% ok)",
        f"- Avg latency: **{s['overall_avg_ms']} ms** · "
        f"Throughput: **{s['throughput_rps']} rps**",
        f"- Highest severity: **{s['highest_severity']}**\n",
        f"> {ins.summary}\n",
        f"- **Benchmark:** {ins.benchmark}",
        f"- **Optimization:** {ins.optimization}",
        f"- **Forecast:** {ins.prediction}\n",
        "## Endpoints\n",
        "| Method | URL | Att | OK% | avg | p95 | p99 | max |",
        "|---|---|--:|--:|--:|--:|--:|--:|",
    ]
    for e in report.endpoints:
        out.append(
            f"| {e.method} | {e.url} | {e.attempts} | {e.success_rate:.1f} "
            f"| {e.avg_ms:.0f} | {e.p95:.0f} | {e.p99:.0f} | {e.max_ms:.0f} |")
    out.append(f"\n## Security findings ({len(report.vulnerabilities)})\n")
    if report.vulnerabilities:
        out.append("| Severity | Type | Endpoint | Remediation |")
        out.append("|---|---|---|---|")
        for v in report.vulnerabilities:
            out.append(f"| {v.severity.value} | {v.type} | {v.endpoint} "
                       f"| {v.remediation} |")
    else:
        out.append("_No weaknesses detected._")
    if ins.assertions:
        out.append("\n## Suggested assertions\n")
        out += [f"- `{a}`" for a in ins.assertions]
    return "\n".join(out) + "\n"


def write_reports(
    report: RunReport, out_dir: str, formats: list[str] | None = None
) -> dict[str, str]:
    """Write requested formats. Returns {format: path}. Default: all."""
    formats = formats or ["json", "csv", "md", "html"]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = Path(out_dir) / f"aegis_report_{stamp}"
    written: dict[str, str] = {}

    if "json" in formats:
        p = f"{base}.json"
        Path(p).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        written["json"] = p
    if "csv" in formats:
        p = f"{base}.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Method", "URL", "Attempts", "Successes", "Failures",
                        "Success%", "Avg ms", "p95 ms", "p99 ms", "Max ms"])
            for e in report.endpoints:
                w.writerow([e.method, e.url, e.attempts, e.successes, e.failures,
                            f"{e.success_rate:.1f}", f"{e.avg_ms:.2f}",
                            f"{e.p95:.2f}", f"{e.p99:.2f}", f"{e.max_ms:.2f}"])
            w.writerow([])
            w.writerow(["Severity", "Type", "Endpoint", "Description",
                        "Remediation", "Source"])
            for v in report.vulnerabilities:
                w.writerow([v.severity.value, v.type, v.endpoint,
                            v.description, v.remediation, v.source])
        written["csv"] = p
    if "md" in formats:
        p = f"{base}.md"
        Path(p).write_text(render_markdown(report), encoding="utf-8")
        written["md"] = p
    if "html" in formats:
        p = f"{base}.html"
        Path(p).write_text(render_html(report), encoding="utf-8")
        written["html"] = p
    if "sarif" in formats:
        from .reporting.exporters.sarif import write_sarif
        written["sarif"] = write_sarif(report, f"{base}.sarif")
    return written
