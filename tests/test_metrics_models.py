from aegis.metrics import MetricsCollector
from aegis.models import (AttemptResult, EndpointStats, RunReport, Severity,
                          TestPlan)


def _attempt(url, code, lat, ok=True, err=None, sample=False):
    return AttemptResult(
        url=url, method="GET", status_code=code, latency_ms=lat, ok=ok,
        error=err,
        sample_body='{"a":1}' if sample else None,
        sample_headers={"Content-Type": "application/json"} if sample else None,
    )


def test_percentiles_exact():
    e = EndpointStats(url="u", method="GET")
    e.latencies = [float(i) for i in range(1, 101)]  # 1..100
    assert round(e.p50) == 50
    assert round(e.p90) == 90
    assert round(e.p99) == 99
    assert e.min_ms == 1 and e.max_ms == 100


def test_single_latency_no_crash():
    e = EndpointStats(url="u", method="GET")
    e.latencies = [42.0]
    assert e.p95 == 42.0 and e.stdev_ms == 0.0


def test_collector_aggregation():
    c = MetricsCollector()
    c.add(_attempt("https://x/a", 200, 100, sample=True))
    c.add(_attempt("https://x/a", 500, 200, ok=False, err="Boom"))
    c.add(_attempt("https://x/b", 200, 50))
    eps = c.finalize()
    assert c.total == 3 and c.successes == 2 and c.failures == 1
    a = next(e for e in eps if e.url.endswith("/a"))
    assert a.attempts == 2 and a.errors == {"Boom": 1}
    assert a.sample_body == '{"a":1}'  # only first sampled
    assert a.status_codes == {200: 1, 500: 1}


def test_plan_mode():
    assert TestPlan(duration_seconds=30).mode() == "duration"
    assert TestPlan(duration_seconds=0).mode() == "count"


def test_runreport_serialisation_and_severity():
    r = RunReport(started_at="now", plan=TestPlan())
    c = MetricsCollector()
    c.add(_attempt("https://x/a", 200, 100, sample=True))
    r.endpoints = c.finalize()
    r.total_attempts, r.total_successes = 1, 1
    d = r.to_dict()
    assert d["app"] == "AEGIS"
    assert d["summary"]["success_rate"] == 100.0
    assert r.highest_severity == Severity.INFO


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank
