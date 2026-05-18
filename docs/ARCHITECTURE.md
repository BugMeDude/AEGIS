# AEGIS — Architecture

## One pipeline, two front-ends

The CLI and GUI are thin shells. All behaviour lives in
`orchestrator.Orchestrator`:

```
            ┌─────────────┐      ┌─────────────┐
            │   cli.py    │      │   gui.py    │
            └──────┬──────┘      └──────┬──────┘
                   └─────────┬──────────┘
                       Orchestrator
   parse ─▶ plan(AI│user) ─▶ safety gate ─▶ engine ─▶ security ─▶ insight ─▶ RunReport
     │           │               │            │          │           │
 parsers.py   ai/brain.py     safety.py    engine.py  ai/brain.py  ai/brain.py
```

Every stage emits an `on_event(name, data)` callback so both front-ends can
render live progress without knowing pipeline internals.

## Modules

| Module | Responsibility | Key types |
|---|---|---|
| `models.py` | Plain, JSON-serialisable domain objects. Percentile math lives on `EndpointStats`. | `RequestSpec`, `TestPlan`, `AttemptResult`, `EndpointStats`, `Vulnerability`, `AIInsight`, `RunReport` |
| `config.py` | Layered config loading; the `SafetyPolicy`. | `AegisConfig`, `OllamaConfig`, `SafetyPolicy` |
| `safety.py` | The authorization gate: classify targets, clamp plans, refuse. | `enforce()`, `SafetyError` |
| `parsers.py` | Robust input parsing with auto-detection. | `parse_any()` |
| `engine.py` | Async load/stress core. Count & duration models, RPS pacing, ramp-up, cooperative stop, response sampling. | `LoadEngine`, `run_engine()` |
| `metrics.py` | Single-context streaming aggregator → percentiles. | `MetricsCollector` |
| `ai/ollama.py` | Resilient HTTP client. Fails soft (returns `None`), strips Markdown JSON fences. | `OllamaClient` |
| `ai/brain.py` | The reasoning core: plan / nlp / security / insight, each with an LLM path **and** a heuristic path. | `AIBrain` |
| `ai/prompts.py` | Prompt templates (strict-JSON contracts). | — |
| `reporting.py` | JSON / CSV / Markdown / standalone HTML. | `write_reports()` |
| `orchestrator.py` | The pipeline + `autopilot()` + `from_nlp()`. | `Orchestrator` |

## The async engine

`LoadEngine.run()` opens one `httpx.AsyncClient` with a connection pool sized
to the concurrency, then spawns N worker coroutines:

- **Count model** (`duration_seconds == 0`): workers pull from a shared counter
  until `total_requests` is reached.
- **Duration model** (`duration_seconds > 0`): workers loop until a monotonic
  deadline.
- **RPS pacing**: an inter-request sleep of `concurrency / target_rps` per
  worker throttles aggregate throughput.
- **Ramp-up**: per-worker staggered start delays.
- **Cooperative stop**: every worker checks `should_stop()` each iteration.
- **Sampling**: the first response per `(method, url)` is captured (body +
  headers, truncated) for the security analyser — bounding memory under load.

A background reporter coroutine emits a metrics snapshot every 0.4 s.

## The AI strategy: augment, never depend

`AIBrain` always runs the deterministic heuristic path. When Ollama is
reachable it *also* runs the LLM path and merges/prefers it:

- **Security**: heuristic findings (missing headers, SQL-error/stack-trace/
  sensitive-data leakage, cleartext, permissive CORS, no rate-limit…) are
  unioned with LLM findings, then de-duplicated keeping the highest severity.
- **Plan / NLP / Insight**: LLM result is validated and type-coerced; on any
  failure (timeout, malformed JSON, daemon down) the heuristic result is used.

Result: identical, well-formed output shape online or offline — this is why
the test suite is deterministic with `ollama.enabled = False`.

## Safety model

`safety.enforce()` is called by the orchestrator **before any socket opens**:

1. Reject empty request sets.
2. Reject any host on `blocklist`.
3. If `allowlist` is non-empty, reject hosts not on it (locals exempt).
4. Reject non-local hosts unless `authorized` is affirmed.
5. Clamp `concurrency`, `duration`, `total_requests` to policy caps and return
   advisory notes.

Localhost / `127.0.0.1` / `::1` / `*.local` are always permitted so a lab
workflow needs no extra flags.

## Concurrency boundaries

- Engine: `asyncio`, single thread, single event loop.
- CLI: `asyncio.run()` in the main thread.
- GUI: engine runs in a daemon worker thread; results cross back via a
  `queue.Queue` drained by a Tk `after()` poll — the UI thread never blocks and
  never touches Tk from the worker.
