"""TLS fingerprint randomization (JA3/JA3S spoofing).

Supports impersonation of common TLS stacks:
  - Chrome, Firefox, Safari
  - iOS, Android mobile browsers
  - Random mode for each connection
"""

from __future__ import annotations

import random
from typing import Any

from ..config import TLSFingerprint

# JA3 fingerprints for common browsers
JA3_FINGERPRINTS = {
    "chrome": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-35-13-16-11-10-65281-5-18-51-45-43-27-21-17513-2570,29-23-24-25-256-257-258,0-1-2",
    "firefox": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24-25-256-257-258,0-1-2",
    "safari": "771,4865-4866-4867-49196-49195-52393-52392-49199-49200-49162-49161-49171-49172-156-157-47-53,0-23-13-16-11-10-35-5-65281-18-51-45-43-27-21-17513,29-23-24-25-257,0-1-2",
    "ios": "771,4865-4866-4867-49196-49195-52393-52392-49199-49200-49162-49161-49171-49172-156-157-47-53,0-23-13-16-11-10-35-5-65281-18-51-45-43-27-21-17513,29-23-24-25-257,0-1-2",
    "android": "771,4865-4866-4867-49196-49195-49199-49200-52393-52392-49171-49172-156-157-47-53,0-23-13-16-11-10-35-5-65281-18-51-45-43-27-21,29-23-24-25-257,0-1-2",
}


class TLSRandomizer:
    """Randomize TLS fingerprint per connection."""

    def __init__(self, cfg: TLSFingerprint) -> None:
        self.cfg = cfg

    def get_ja3(self) -> str:
        """Get JA3 fingerprint string based on configuration."""
        if self.cfg.randomize:
            return random.choice(list(JA3_FINGERPRINTS.values()))
        if self.cfg.impersonate and self.cfg.impersonate in JA3_FINGERPRINTS:
            return JA3_FINGERPRINTS[self.cfg.impersonate]
        return ""

    def get_headers(self) -> dict[str, str]:
        """Get browser-specific headers for HTTP impersonation."""
        if self.cfg.impersonate == "chrome":
            return {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }
        elif self.cfg.impersonate == "firefox":
            return {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
                              "Gecko/20100101 Firefox/120.0",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
            }
        elif self.cfg.impersonate in ("safari", "ios"):
            return {
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                              "Mobile/15E148 Safari/604.1",
                "Accept-Language": "en-US,en;q=0.9",
            }
        return {}
