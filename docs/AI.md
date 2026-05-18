# AEGIS — The AI Layer

## Model

AEGIS uses your local **Ollama** daemon. Default model: **`gemma4:31b-cloud`**
(the cloud-proxied model present on this machine), with **`gemma4:latest`** as
the automatic local fallback if the primary is missing.

```yaml
ollama:
  host: "http://localhost:11434"
  model: "gemma4:31b-cloud"
  fallback_model: "gemma4:latest"
  timeout_seconds: 90
  temperature: 0.1
  enabled: true
```

`OllamaClient.health()` queries `/api/tags`; if the configured model isn't
listed it transparently selects the fallback (or the first available model).

## What the AI does

| Capability | Prompt (`ai/prompts.py`) | LLM output | Heuristic fallback |
|---|---|---|---|
| **Plan** | `PLANNER_*` | concurrency, model, duration/count, ramp, rationale | goal keywords → soak/stress/baseline presets |
| **NLP** | `NLP_*` | URL, method, headers, body, load params | regex extraction of URL/verb/token/numbers |
| **Security** | `SECURITY_*` | findings: type, severity, description, remediation, evidence | header/body rule engine (SQLi errors, stack traces, sensitive data, missing headers, cleartext, CORS, rate-limit…) |
| **Insight** | `SUMMARY_*` | exec summary, benchmark, optimization, forecast, assertions, grade | metric-driven templated summary + scored grade |

## Resilience: fail soft, always answer

`OllamaClient` never raises to the caller — every method returns `None` on
timeout / connection error / HTTP error and marks itself unavailable. Gemma
wraps JSON in Markdown fences (```json … ```); `_extract_json()` strips fences
and, failing that, regex-extracts the first `{...}`/`[...]` and parses it.

`AIBrain` **always** computes the heuristic result first, then overlays the
LLM result only if it validates. Consequences:

- Ollama down, `--no-ai`, or `AEGIS_NO_AI=1` → full functionality, heuristic
  output, `engine = "heuristic"`.
- Ollama up → richer contextual reasoning, `engine = "ollama:<model>"`.
- The output **shape never changes**, which is why the 40-test suite is
  deterministic offline.

## Security analysis is defensive

The security prompt is explicitly scoped to a **defensive assessment of
captured responses** during an *authorised* test: identify weaknesses
(missing/weak headers, info disclosure, sensitive data, error leakage,
transport/auth issues, missing rate limiting) and give concrete remediation.
It does not generate exploits or attack payloads. Heuristic and LLM findings
are merged and de-duplicated, keeping the highest severity per
`(type, endpoint)`.

## Tuning

- Lower `temperature` (default `0.1`) for more deterministic plans/grades.
- Raise `timeout_seconds` for large local models; the cloud model is ~1–2 s.
- Swap `model` per environment via `AEGIS_OLLAMA_MODEL` without code changes.
- Prompts are data in `ai/prompts.py` — edit them without touching control
  flow; the JSON contract is what `brain.py` depends on.
