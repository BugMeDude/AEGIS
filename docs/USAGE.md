# AEGIS — Usage Guide

All commands work as `python3 -m aegis <cmd>` or, after `pip install -e .`,
simply `aegis <cmd>`.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Environment, Ollama and policy health check. No traffic. |
| `plan` | Show the AI-proposed test plan only. No traffic. |
| `run` | Load + security test with a plan **you** specify. |
| `autopilot` | Fully automated — the AI designs the plan, runs, analyses. |
| `scan` | **Offensive + defensive** active DAST scan (education/research). |
| `ai` | Natural-language driven test. |
| `report` | Re-render a saved `aegis_report_*.json` to HTML/MD/CSV. |
| `init` | Write a commented `aegis.yaml`. |
| `gui` | Launch the desktop application. |
| `version` | Print version. |

### Input argument

`run`, `autopilot`, `plan` take one `input` that can be:

- a **literal** string: `"curl https://x.com -H 'A: 1'"` or `"https://x.com"`
- a **file path**: `collection.json`, `api.yaml`, `traffic.har`, `reqs.txt`
- `-` to read from **stdin**: `cat reqs.curl | python3 -m aegis run -`

Format is auto-detected; force it with `--type {auto,curl,postman,openapi,har,url}`.

### `run` — operator-controlled

```bash
python3 -m aegis run api.json \
  --type postman \
  --concurrency 50 \      # -n  parallel connections
  --duration 30 \         # -d  seconds (>0 ⇒ duration model; 0 ⇒ count model)
  --requests 5000 \       # -r  total requests (count model)
  --rps 200 \             #     pace to ~200 req/s (0 = unthrottled)
  --ramp 5 \              #     linear ramp-up over 5s
  --timeout 15 \
  --offensive \           # -O  add an active DAST scan (education/research)
  --formats json,html,md \
  --authorized            # required for non-local targets
```

`--ai-plan` ignores the manual numbers and asks the AI to design the plan
instead. `--no-ai` forces the deterministic heuristic engine.

### `autopilot` — zero-config

```bash
python3 -m aegis autopilot https://staging.api.com/v1/health \
  --goal "stress test" --authorized
```

`--goal` steers the AI: e.g. `"soak test"`, `"spike test"`, `"baseline"`,
`"find the breaking point"`. The AI returns concurrency, model (count vs
duration), ramp-up and a rationale — all still clamped by the safety policy.

### `scan` — offensive + defensive (education / research)

```bash
# Dedicated active scan (light baseline load + injection probes)
python3 -m aegis scan "https://lab.local/api/item?id=1" --authorized

# Or bolt an active scan onto any run / autopilot with -O / --offensive
python3 -m aegis run api.har -O --authorized
python3 -m aegis autopilot https://lab.local/v1 -O --goal "stress" --authorized
```

The scanner discovers injection points (query + form params) and sends a
small, curated, well-known set of teaching payloads, then classifies the
responses:

| Class | Detection |
|---|---|
| SQL injection (error & time-based) | DB error signatures / response-delay delta |
| Reflected XSS | unencoded payload reflection |
| Path traversal / LFI | OS file-content signatures (`root:x:0:0:`) |
| OS command injection | `id` output (`uid=`,`gid=`) |
| Server-side template injection | `{{7*7}}` → `49` |
| Open redirect | attacker-controlled `Location` |
| Access-control bypass | `X-Forwarded-For/-Host`, `X-Original-URL` flip 401/403 → 200 |

Every finding includes **evidence** and a concrete **remediation** (the
defensive half). It is bounded by design — a teaching instrument, not a
flooder — and only runs after the authorization gate passes. **Education and
authorised research only.**

### `ai` — natural language

```bash
python3 -m aegis ai "hit https://x.com/api 300 times with 20 concurrent" --authorized
python3 -m aegis ai "soak https://x.com for 2 minutes" --authorized
```

The LLM extracts the URL, method, headers, body and load parameters. A regex
fallback handles the offline case.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no High/Critical findings |
| 1 | Runtime error |
| 2 | No requests could be parsed from the input |
| 3 | Refused by the responsible-use policy |
| 4 | Completed, but a **High or Critical** security finding exists |

Code 4 makes AEGIS CI-friendly: fail a pipeline when the API regresses on
security.

## Configuration

Precedence: defaults < `aegis.yaml` < `AEGIS_*` env vars < CLI flags.

```bash
python3 -m aegis init           # writes aegis.yaml
```

```yaml
ollama:
  model: "gemma4:31b-cloud"
  fallback_model: "gemma4:latest"
  enabled: true
safety:
  authorized: false
  max_concurrency: 250
  max_duration_seconds: 600
  allowlist: ["api.staging.mycorp.com"]   # if set, ONLY these (+ local) allowed
  blocklist: []
report_dir: "aegis_reports"
```

Env shortcuts: `AEGIS_OLLAMA_MODEL`, `AEGIS_OLLAMA_HOST`, `AEGIS_NO_AI=1`,
`AEGIS_AUTHORIZED=1`, `AEGIS_REPORT_DIR`.

## Reports

Written to `report_dir` (default `aegis_reports/`):

- **`.json`** — full machine-readable report (CI, diffing, `aegis report`)
- **`.html`** — self-contained dark-theme dashboard, no external assets
- **`.md`** — pull-request / wiki friendly
- **`.csv`** — endpoint + findings tables for spreadsheets

## GUI

`python3 -m aegis gui`

- Three modes: **Manual plan**, **🤖 Autopilot**, **Natural language**
- Live progress (RPS, avg latency, %), cooperative **Stop**
- Tabs: Summary · Endpoints · Security · Chart
- One-click export to HTML/JSON/MD/CSV
- The “I am authorised…” checkbox maps to the safety gate

The engine runs in a worker thread; the UI never blocks.
