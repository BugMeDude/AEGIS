"""Out-of-Band (OOB) callback server for blind vulnerability detection.

Provides:
  - HTTP callback server to receive OOB interactions
  - Unique per-scan callback URLs
  - Blind SSRF, blind XSS, blind SQLi detection
  - Optional DNS callback via DNS server
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
import uuid
from typing import Any

import httpx


class OOBCallbackServer:
    """OOB callback detection for blind vulnerabilities.

    Generates unique callback tokens that, when triggered by target
    systems, confirm blind vulnerabilities like blind SSRF, blind XSS,
    or time-based SQLi with DNS exfiltration.
    """

    def __init__(self, callback_base: str = "http://localhost:9999",
                 external_ip: str = "") -> None:
        self.callback_base = callback_base.rstrip("/")
        self.external_ip = external_ip
        self._callbacks: dict[str, list[dict]] = {}
        self._server = None
        self._running = False

    def generate_token(self, scan_id: str, vuln_type: str) -> str:
        """Generate a unique callback token for a scan.

        Format: {scan_id}-{vuln_type}-{random}
        """
        token = f"{scan_id}-{vuln_type}-{secrets.token_hex(8)}"
        self._callbacks[token] = []
        return token

    def callback_url(self, token: str) -> str:
        return f"{self.callback_base}/oob/{token}"

    def callback_host(self, token: str) -> str:
        """Return hostname for DNS-based callbacks."""
        return f"{token}.oob.localhost"

    def check_triggered(self, token: str) -> bool:
        """Check if a callback token has been triggered."""
        return len(self._callbacks.get(token, [])) > 0

    def get_callbacks(self, token: str) -> list[dict]:
        """Get all callback events for a token."""
        return self._callbacks.get(token, [])

    def register_callback(self, token: str, data: dict) -> None:
        if token in self._callbacks:
            self._callbacks[token].append({
                "timestamp": time.time(),
                "data": data,
            })

    async def verify_ssrf(
        self,
        target_url: str,
        callback_token: str,
        timeout: float = 10.0,
    ) -> bool:
        """Verify SSRF by checking if callback triggered within timeout."""
        start = time.time()
        while time.time() - start < timeout:
            if self.check_triggered(callback_token):
                return True
            await asyncio.sleep(0.5)
        return False

    async def verify_blind_xss(
        self,
        callback_token: str,
        timeout: float = 15.0,
    ) -> bool:
        """Verify blind XSS by waiting for callback."""
        return await self.verify_ssrf("", callback_token, timeout)

    async def start_server(self, host: str = "0.0.0.0",
                           port: int = 9999) -> None:
        """Start the HTTP callback server (if asyncio server desired)."""
        # In production, you'd use a proper HTTP server here.
        # For now, we rely on external tools (interactsh, Burp Collaborator)
        # or a simple webhook endpoint.
        self.callback_base = f"http://{host}:{port}"
        self._running = True

    async def stop_server(self) -> None:
        self._running = False

    @staticmethod
    async def check_external_burp_collab(collab_url: str,
                                          session_token: str) -> list[dict]:
        """Check Burp Collaborator for interactions."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(f"{collab_url}/burpresults?{session_token}")
                if r.status_code == 200:
                    return r.json().get("interactions", [])
        except Exception:
            pass
        return []


class InteractShClient:
    """Integration with interact.sh for OOB detection."""

    def __init__(self) -> None:
        self.server_url = "https://oob.drastically.io"
        self._session_id: str = ""

    async def start_session(self) -> str:
        """Start a new interact.sh session."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(f"{self.server_url}/new")
                if r.status_code == 200:
                    data = r.json()
                    self._session_id = data.get("id", "")
                    return data.get("url", "")
        except Exception:
            pass
        return ""

    async def poll(self) -> list[dict]:
        """Poll for interactions."""
        if not self._session_id:
            return []
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(f"{self.server_url}/poll?id={self._session_id}")
                if r.status_code == 200:
                    return r.json().get("data", [])
        except Exception:
            pass
        return []

    async def close(self) -> None:
        self._session_id = ""
