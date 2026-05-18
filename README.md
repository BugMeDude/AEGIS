# 🛡 AEGIS

### Autonomous API Stress & Security Intelligence Platform

> A complete, AI-driven rebuild of the original *Ethical Hacker API Tester*
> (2024). AEGIS turns a single cURL command, URL, Postman collection,
> OpenAPI spec or plain-English sentence into a load test **and** a security
> assessment **and** an executive report — automatically.

Built and maintained by **BugMeDude**. Version **2.0.0**.

> ## 🎓 Educational & Research Edition — Offensive + Defensive
> **AEGIS is built for students, security researchers and authorised
> penetration testers** to learn — hands-on — how API load, resilience and
> injection-class vulnerabilities (SQLi, XSS, traversal, command/template
> injection, open redirect, header auth-bypass) actually work, *and how to
> defend against them*. It pairs an **offensive** active scanner with
> **defensive** passive analysis and AI remediation guidance.
>
> **Use it ONLY on systems you own or are explicitly authorised to test.**
> Unauthorised testing is illegal and is solely the user's responsibility.
> A hard authorization gate + load caps enforce this in code.

---

## Why this is a rebuild, not a patch

| | Original (2024) | AEGIS 2.0 |
|---|---|---|
| Concurrency | `ThreadPoolExecutor`, blocking | `asyncio` + `httpx`, hundreds of conns |
| Metrics | avg / min / max only | p50/p90/p95/p99, stdev, RPS, status map |
| "AI" | regex & if/else heuristics | **real LLM** (`gemma4:31b-cloud`) + heuristic fallback |
| Automation | none — GUI clicks only | **Autopilot**: AI plans → runs → analyses → reports |
| Interfaces | Tkinter only | unified **CLI** + modern **GUI** + Python API |
| Inputs | cURL, Postman | + OpenAPI 3, Swagger 2, HAR, URL lists, NLP |
| Reports | CSV / TXT | JSON, CSV, Markdown, self-contained **HTML dashboard** |
| Offensive | exploit-hint strings only | **active DAST scanner**: real SQLi/XSS/traversal/cmd/SSTI/redirect/header-bypass probes with detectors |
| Safety | none | authorization gate + concurrency/duration caps |
| Tests | none | 45 automated tests, live integration verified |

The 2024 legacy sources have been **removed**; the project is now the single
self-contained [`aegis/`](aegis/) package (see `CHANGELOG.md`).

---

## Install

```bash
cd /home/edc1840/Desktop/StressTest
python3 -m pip install -r requirements.txt      # all deps already present on this box
# optional: install the `aegis` command system-wide
python3 -m pip install -e .
```

Everything also works with no install via `python3 -m aegis …`.

## 60-second tour

```bash
# 1. Health check (Python, Ollama model, policy)
python3 -m aegis doctor

# 2. Fully automated — the AI designs and runs the whole test
python3 -m aegis autopilot "http://127.0.0.1:8799/api" --goal "baseline"

# 3. Plain English
python3 -m aegis ai "stress https://staging.myapp.com for 30s, 50 concurrent" --authorized

# 4. You control the plan
python3 -m aegis run requests.curl -n 50 -d 30 --formats html,json

# 5. Offensive + defensive vulnerability scan (education / authorised research)
python3 -m aegis scan "http://127.0.0.1:8799/item?id=1"
#   …or add an active scan to any run/autopilot:
python3 -m aegis autopilot https://lab.local/api -O --authorized

# 6. Desktop app  (has an "⚔ Offensive active scan" toggle)
python3 -m aegis gui
```

`requests.curl` can be a file, a literal cURL/URL string, or `-` for stdin.
Inputs are auto-detected (cURL / URL / Postman / OpenAPI / HAR) — override with
`--type`.

## Responsible use 🔒

AEGIS is a dual-use appsec tool. It **refuses to generate load against any
non-local host** unless you affirm authorization (`--authorized`, or
`safety.authorized: true`, or `AEGIS_AUTHORIZED=1`). Concurrency, duration and
total-request **caps** are always enforced so a typo can't become a DoS. Only
test systems you own or are explicitly contracted to assess.

## AI

AEGIS talks to your local Ollama daemon (default model `gemma4:31b-cloud`).
The LLM does four jobs: **plan** the test, parse **natural language**, reason
about **security** of captured responses, and write the **executive insight**.
If Ollama is unreachable or `--no-ai` is set, a deterministic heuristic engine
takes over — every feature still works, output stays well-formed. See
[`docs/AI.md`](docs/AI.md).

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — every command, flag and workflow
- [`docs/SECURITY.md`](docs/SECURITY.md) — offensive + defensive module, responsible use
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map & data flow
- [`docs/AI.md`](docs/AI.md) — the AI layer, prompts, fallback model

## Testing

```bash
python3 -m pytest -q          # 45 tests, ~10s, fully offline & deterministic
```

The suite spins up real local HTTP servers (one deliberately vulnerable) and
exercises the async engine, parsers, safety gate, reporting, the heuristic AI
path **and the offensive scanner's detectors** end-to-end.

## Project layout

```
aegis/
  models.py        domain dataclasses (RequestSpec, TestPlan, RunReport…)
  config.py        YAML/env config + SafetyPolicy
  safety.py        the authorization gate
  parsers.py       cURL / Postman / OpenAPI / HAR / URL / auto-detect
  engine.py        async load/stress engine (count & duration models)
  offense.py       active DAST scanner (offensive, education/research)
  metrics.py       streaming aggregation → percentiles
  ai/ollama.py     resilient Ollama client (JSON-fence safe)
  ai/brain.py      AIBrain: plan / nlp / security / insight (+ fallbacks)
  ai/prompts.py    prompt templates
  reporting.py     JSON / CSV / Markdown / HTML dashboard
  orchestrator.py  the pipeline shared by CLI, GUI and autopilot
  cli.py           Typer + Rich command line
  gui.py           modern ttk desktop app
tests/             40 automated tests
docs/              architecture / usage / AI guides
```

## License

MIT — see [`LICENSE`](LICENSE).
