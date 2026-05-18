import pytest

from aegis.config import SafetyPolicy
from aegis.models import RequestSpec, TestPlan
from aegis.safety import SafetyError, classify_targets, clamp_plan, enforce


def _spec(url):
    return RequestSpec(url=url).normalised()


def test_local_targets_allowed_without_authorization():
    pol = SafetyPolicy(authorized=False)
    notes = enforce([_spec("http://127.0.0.1:8000/a")], TestPlan(), pol)
    assert isinstance(notes, list)


def test_remote_target_refused_without_authorization():
    pol = SafetyPolicy(authorized=False)
    with pytest.raises(SafetyError, match="authorization"):
        enforce([_spec("https://api.example.com/a")], TestPlan(), pol)


def test_remote_target_allowed_when_authorized():
    pol = SafetyPolicy(authorized=True)
    enforce([_spec("https://api.example.com/a")], TestPlan(), pol)


def test_blocklist_always_refused():
    pol = SafetyPolicy(authorized=True, blocklist=("evil.com",))
    with pytest.raises(SafetyError, match="blocklist"):
        enforce([_spec("https://evil.com/a")], TestPlan(), pol)


def test_allowlist_enforced():
    pol = SafetyPolicy(authorized=True, allowlist=("good.com",))
    enforce([_spec("https://good.com/a")], TestPlan(), pol)
    with pytest.raises(SafetyError, match="allowlist"):
        enforce([_spec("https://other.com/a")], TestPlan(), pol)


def test_plan_clamped_to_caps():
    pol = SafetyPolicy(max_concurrency=50, max_duration_seconds=60,
                        max_total_requests=1000)
    plan = TestPlan(concurrency=999, duration_seconds=9999)
    notes = clamp_plan(plan, pol)
    assert plan.concurrency == 50 and plan.duration_seconds == 60
    assert len(notes) == 2


def test_empty_requests_refused():
    with pytest.raises(SafetyError):
        enforce([], TestPlan(), SafetyPolicy())


def test_classify_targets():
    info = classify_targets(
        [_spec("http://localhost/a"), _spec("https://x.com/b")],
        SafetyPolicy())
    assert "x.com" in info["hosts"] and not info["all_local"]
