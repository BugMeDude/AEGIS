# Changelog

## 2.0.0 — AEGIS (full rebuild of "Ethical Hacker API Tester")

Complete ground-up rewrite. The 2024 originals are preserved untouched
alongside the new `aegis/` package.

### Added
- Async `asyncio`+`httpx` load/stress engine with **count** and **duration**
  models, RPS pacing, ramp-up, cooperative stop and response sampling.
- True latency statistics: p50/p90/p95/p99, stdev, throughput, status map.
- **Real LLM reasoning** via Ollama (`gemma4:31b-cloud`, auto-fallback to
  `gemma4:latest`) for planning, NLP, security analysis and executive insight,
  each with a deterministic heuristic fallback.
- **Autopilot**: fully automated parse → AI-plan → run → analyse → report.
- Unified **Typer + Rich CLI** (`doctor/plan/run/autopilot/ai/report/init/gui`)
  with CI-friendly exit codes.
- **Modern ttk GUI**: non-blocking worker thread, live metrics, tabbed results,
  embedded latency chart, one-click multi-format export.
- Input parsers: cURL (real `shlex`), Postman v2 (recursive + variables),
  OpenAPI 3 / Swagger 2, HAR, URL lists, auto-detection.
- Reports: JSON, CSV, Markdown, self-contained HTML dashboard.
- **Responsible-use safety gate**: authorization affirmation + concurrency /
  duration / total-request caps, host allow/block lists.
- Layered configuration (defaults < YAML < env < CLI).
- 40 automated tests (parsers, metrics, safety, live engine, AI fallback,
  reporting) + verified live integration with the engine and Ollama.
- Documentation: README, USAGE, ARCHITECTURE, AI guides.

### Changed
- "AI" modules that were regex/if-else heuristics are now genuine LLM calls
  with those heuristics retained only as the offline fallback path.
- GUI logic fully separated from UI via `Orchestrator`.

### Education & Research Edition
- New **offensive active DAST scanner** (`offense.py`): bounded, curated
  probes for SQLi (error & time-based), XSS, path traversal, OS command
  injection, SSTI, open redirect and header-based access-control bypass —
  each finding paired with concrete remediation (offensive **and** defensive).
- `aegis scan` command + `-O/--offensive` flag on `run`/`autopilot` + GUI
  toggle; gated by the same authorization safety check.
- Education/research caption + responsible-use notice surfaced in the CLI
  banner, `doctor`, the GUI header, and every HTML/Markdown report.
- 5 new tests against a deliberately-vulnerable local app (45 total).
- New `docs/SECURITY.md`.

### Removed
- Blocking `ThreadPoolExecutor` engine; hardcoded 2000×1100 window. The old
  ad-hoc exploit-hint strings are replaced by a real, bounded scanner whose
  findings always include defensive remediation.

### Cleanup
- Removed all 2024 legacy sources (`ApiTester.py`, `APIEndpoint.py`,
  `ApiRequestHandler.py`, `GuiManager.py`, `features/`), stale bytecode caches
  and unused assets. The project is now the single self-contained `aegis/`
  package.
