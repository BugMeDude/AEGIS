"""Offensive active-scanner tests against a deliberately-vulnerable local app.

The toy server intentionally mis-handles input so the scanner's detectors can
be verified end to end (no mocks). Educational/research use only.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from aegis.offense import OffensiveScanner, active_scan
from aegis.models import RequestSpec, Severity


class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        val = (q.get("q") or q.get("id") or [""])[0]
        body = f"<html>echo: {val}</html>"          # reflected XSS
        if "'" in val or '"' in val:
            body = "You have an error in your SQL syntax near '" + val
        if "etc/passwd" in val or "etc%2fpasswd" in val:
            body = "root:x:0:0:root:/root:/bin/bash\n"
        if "id" in val and any(c in val for c in ";|`$"):
            body = "uid=0(root) gid=0(root) groups=0(root)"
        if "SLEEP" in val.upper() or "pg_sleep" in val.lower():
            time.sleep(3.2)
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture(scope="module")
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    h, p = srv.server_address
    yield f"http://{h}:{p}"
    srv.shutdown()


def test_detects_sqli_xss_traversal_cmdi(vuln_server):
    spec = RequestSpec(url=f"{vuln_server}/item?q=1").normalised()
    findings = active_scan([spec], timeout=8.0)
    types = {f.type for f in findings}
    assert "SQL Injection (error-based)" in types
    assert "Reflected XSS" in types
    assert "Path Traversal / LFI" in types
    assert "OS Command Injection" in types
    assert any(f.severity == Severity.CRITICAL for f in findings)
    # Every finding carries remediation + evidence + correct source.
    for f in findings:
        assert f.remediation and f.evidence and f.source == "active-scan"


def test_time_based_sqli(vuln_server):
    spec = RequestSpec(url=f"{vuln_server}/x?id=1").normalised()
    findings = active_scan([spec], timeout=10.0)
    assert any("time-based" in f.type for f in findings)


def test_scanner_safe_on_clean_endpoint(http_server):
    # The conftest server echoes nothing exploitable.
    spec = RequestSpec(url=f"{http_server}/clean?q=1").normalised()
    findings = active_scan([spec], timeout=6.0)
    assert all(f.severity.rank <= Severity.MEDIUM.rank for f in findings)


def test_scanner_handles_dead_target():
    spec = RequestSpec(url="http://127.0.0.1:1/nope?q=1").normalised()
    # Must not raise; just yields no/empty findings.
    assert active_scan([spec], timeout=2.0) == []


def test_injection_point_discovery():
    s = RequestSpec(url="http://x/a?foo=1&bar=2", method="POST",
                    body="baz=3").normalised()
    sc = OffensiveScanner([s])
    from aegis.offense import _points
    pts = {n for _, n in _points(s, 10)}
    assert {"foo", "bar", "baz"}.issubset(pts)
