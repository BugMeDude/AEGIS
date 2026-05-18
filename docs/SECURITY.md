# AEGIS — Offensive + Defensive Security Module

> 🎓 **Education & research only.** AEGIS is for students, researchers and
> authorised penetration testers to *understand* API vulnerabilities and
> *learn to defend* against them. Use only on systems you own or are
> explicitly authorised to test. Unauthorised use is illegal and is solely
> the user's responsibility.

AEGIS analyses security from two complementary angles.

## 1. Defensive — passive analysis (`ai/brain.py`)

Runs on **every** test, no extra flag. Inspects the responses captured during
the load run and flags weaknesses without sending attack traffic:

- Missing/weak security headers (HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options), permissive CORS
- Information disclosure (`Server`, `X-Powered-By`)
- Error / stack-trace / SQL-error leakage
- Sensitive data in bodies, cleartext transport, missing rate-limiting

Each finding is unioned with the LLM's reasoning (when Ollama is up) and
de-duplicated keeping the highest severity. Every item ships a **remediation**.

## 2. Offensive — active scanner (`offense.py`)

Opt-in via `aegis scan`, `-O/--offensive`, or the GUI toggle. This is the same
class of *active* probing performed by OWASP ZAP / Burp active scan / sqlmap,
implemented as a **bounded teaching instrument**:

```
discover injection points (query + form params)
   └─▶ inject curated payload set per class
         └─▶ classify response (signatures / reflection / timing / redirect)
               └─▶ Vulnerability(evidence + remediation, source="active-scan")
```

| Class | Payloads (sample) | Detector |
|---|---|---|
| SQLi (error) | `'`, `' OR '1'='1` | DB error signatures |
| SQLi (time-blind) | `1' AND SLEEP(3)--` | response-time delta > baseline+2.5s |
| Reflected XSS | `<aegisXSS>`, `"'><svg/onload=1>` | verbatim reflection |
| Path traversal | `../../../../etc/passwd` | `root:x:0:0:` etc. |
| OS command injection | `; id`, `` `id` `` | `uid=`,`gid=` in body |
| SSTI | `{{7*7}}` | `49` appears, payload doesn't |
| Open redirect | `//aegis.invalid/owned` | `Location` points off-site |
| Access-control bypass | `X-Forwarded-For/-Host`, `X-Original-URL` | 401/403 → 200 |

### Why this is responsible by construction

- **Authorization gate first.** `safety.enforce()` runs before any probe;
  non-local targets are refused unless authorization is affirmed; block/allow
  lists apply.
- **Bounded.** ≤ ~6 payloads per class, ≤ 6 injection points per request,
  ≤ 25 endpoints, per-request timeout, modest concurrency — it cannot become
  a flooder.
- **Curated, well-known payloads.** The same strings taught in the OWASP
  Testing Guide. No exploit weaponisation, no data exfiltration, no
  persistence.
- **Defensive payoff.** Every offensive finding is paired with concrete
  remediation — the point is to learn the fix, not just the break.
- **Fails safe.** A probe error never aborts the run; the scan degrades to no
  findings.

## CI usage

`aegis` exits **4** when a High/Critical finding exists, so a pipeline can
fail a build on a security regression:

```bash
python3 -m aegis scan openapi.yaml --authorized --no-save || code=$?
[ "${code:-0}" -eq 4 ] && echo "Security regression!" && exit 1
```
