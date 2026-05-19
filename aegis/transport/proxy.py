"""Multi-hop proxy chain and Tor integration for anonymized scanning."""

from __future__ import annotations

import random
from typing import Any

from ..config import ProxyConfig


class ProxyChain:
    """Multi-hop proxy chain for layered anonymity.

    Supports:
      - Single HTTP/HTTPS/SOCKS5 proxy
      - Tor (via stem/ SOCKS5 localhost:9050)
      - Multi-hop proxy chains (rotate through list)
      - Per-request proxy rotation
    """

    def __init__(self, cfg: ProxyConfig) -> None:
        self.cfg = cfg
        self._tor_controller = None
        self._current_index = 0

    def get_proxy_dict(self) -> dict[str, str] | None:
        """Get httpx-compatible proxy dict for current configuration."""
        proxy_url = self.cfg.effective_proxy()
        if not proxy_url:
            return None

        if self.cfg.chain:
            proxy_url = self.cfg.chain[self._current_index % len(self.cfg.chain)]
            if self.cfg.rotate_per_request:
                self._current_index += 1

        return {
            "http://": proxy_url,
            "https://": proxy_url,
        }

    def get_httpx_mounts(self):
        """Get httpx mounts for proxy support."""
        proxy_url = self.cfg.effective_proxy()
        if not proxy_url:
            return None
        return {
            "http://": proxy_url,
            "https://": proxy_url,
        }

    async def renew_tor_identity(self) -> bool:
        """Request a new Tor circuit (requires stem)."""
        if not self.cfg.tor:
            return False
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                self._current_index += 1
                return True
        except Exception:
            return False

    @property
    def is_active(self) -> bool:
        return self.cfg.effective_proxy() is not None

    @staticmethod
    def from_string(proxy_str: str) -> ProxyConfig:
        """Parse a proxy string into a ProxyConfig."""
        cfg = ProxyConfig()
        if proxy_str.startswith("socks5h://"):
            cfg.socks5h = proxy_str[10:]
        elif proxy_str.startswith("socks5://"):
            cfg.socks5 = proxy_str[9:]
        elif proxy_str.startswith("http://"):
            cfg.http = proxy_str
        elif proxy_str.startswith("https://"):
            cfg.https = proxy_str
        elif proxy_str == "tor":
            cfg.tor = True
        else:
            cfg.http = f"http://{proxy_str}"
        return cfg
