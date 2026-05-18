"""Prompt templates for the AIBrain.

Kept in one place so the reasoning behaviour can be tuned without touching
control flow. All prompts instruct strict JSON output; the client tolerates
fenced or prose-wrapped JSON anyway.
"""

PLANNER_SYSTEM = (
    "You are AEGIS-Planner, an expert performance engineer. You design safe, "
    "informative API load-test plans. You never recommend traffic that would "
    "constitute a denial-of-service attack. Reply with strict JSON only."
)

PLANNER_USER = """\
Design a load-test plan for these targets:
{targets}

Operator goal: {goal}
Authorised: {authorized}. Hard caps: concurrency<={max_c}, duration<={max_d}s.

Return JSON:
{{"concurrency": int, "duration_seconds": int, "total_requests": int,
  "target_rps": number, "ramp_up_seconds": int, "rationale": "<1-2 sentences>"}}
If duration_seconds > 0 it is a time-bounded test and total_requests is ignored.
Choose conservative, professional values that reveal latency/percentile
behaviour without overwhelming the target.
"""

NLP_SYSTEM = (
    "You convert a natural-language testing request into a structured spec. "
    "Reply with strict JSON only."
)

NLP_USER = """\
Request: "{query}"

Return JSON:
{{"url": "<full url or empty>", "method": "GET|POST|PUT|DELETE|PATCH",
  "headers": {{}}, "body": "<string or empty>",
  "concurrency": int, "duration_seconds": int, "total_requests": int,
  "rationale": "<short>"}}
Infer sensible numbers from phrases like "for 30 seconds", "100 requests",
"50 concurrent". Use 0 for unknown duration and a request count instead.
"""

SECURITY_SYSTEM = (
    "You are AEGIS-SecAnalyst, a senior application-security reviewer doing a "
    "DEFENSIVE assessment of HTTP responses captured during an authorised "
    "test. Identify real weaknesses and give concrete remediation. Do not "
    "fabricate. Reply with strict JSON only."
)

SECURITY_USER = """\
Endpoint: {method} {url}
Status: {status}
Response headers: {headers}
Response body (truncated): {body}

List security findings as JSON:
{{"findings": [
  {{"type": "<short title>", "severity": "Critical|High|Medium|Low|Info",
    "description": "<what & why>", "remediation": "<concrete fix>",
    "evidence": "<header/body snippet>"}}
]}}
Focus on: missing/weak security headers, info disclosure, sensitive data in
body, error leakage, auth/transport issues, missing rate limiting. Empty list
if genuinely clean.
"""

SUMMARY_SYSTEM = (
    "You are AEGIS-Analyst. You write crisp, executive performance & security "
    "summaries for engineers. Reply with strict JSON only."
)

SUMMARY_USER = """\
Test report data:
{report}

Return JSON:
{{"summary": "<3-5 sentence executive summary of performance & reliability>",
  "benchmark": "<one line verdict vs a <200ms p95 / >99% success bar>",
  "optimization": "<one concrete tuning recommendation>",
  "prediction": "<one sentence risk forecast under higher load>",
  "assertions": ["<up to 5 suggested response assertions>"],
  "grade": "A|B|C|D|F"}}
Base every statement on the numbers provided; be specific (cite p95, rps, error rate).
"""
