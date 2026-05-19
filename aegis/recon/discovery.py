"""Attack surface discovery — endpoints, parameters, authentication realms.

Performs:
  - Endpoint discovery via wordlist brute-forcing
  - Hidden parameter fuzzing
  - Common API path detection
  - Authentication endpoint discovery
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..models import RequestSpec

# Common API endpoint patterns
API_PATHS = [
    "/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/swagger",
    "/openapi", "/docs", "/api-docs", "/swagger.json", "/openapi.json",
    "/health", "/healthz", "/status", "/ping", "/metrics",
    "/login", "/logout", "/signin", "/signup", "/register",
    "/token", "/auth", "/oauth", "/oauth2",
    "/admin", "/manage", "/console", "/dashboard",
    "/users", "/user", "/profile", "/account",
    "/search", "/query", "/graphql",
    "/upload", "/download", "/export", "/import",
    "/config", "/configuration", "/settings",
    "/debug", "/test", "/sandbox", "/eval",
]

# Common parameter names for fuzzing
COMMON_PARAMS = [
    "id", "q", "query", "search", "page", "limit", "offset", "sort",
    "filter", "where", "select", "include", "expand", "fields",
    "callback", "jsonp", "format", "type", "mode",
    "url", "redirect", "return", "next", "goto",
    "file", "path", "page", "dir", "template",
    "debug", "test", "env", "source",
    "token", "api_key", "apikey", "secret", "key",
    "password", "passwd", "pwd", "credential",
    "username", "user", "email", "name",
]

COMMON_SUBDOMAINS = [
    "api", "dev", "staging", "test", "admin", "portal",
    "app", "www", "mail", "cdn", "static", "assets",
    "graphql", "ws", "websocket", "mobile",
]


class DiscoveryEngine:
    """Discovers API endpoints, parameters, and attack surface."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self.discovered_endpoints: list[str] = []
        self.discovered_params: list[str] = []
        self.discovered_auth: list[str] = []

    async def discover_endpoints(
        self,
        base_url: str,
        wordlist: list[str] | None = None,
        max_paths: int = 50,
    ) -> list[str]:
        """Brute-force discover API endpoints from a wordlist."""
        paths = (wordlist or API_PATHS)[:max_paths]
        base = base_url.rstrip("/")
        found: list[str] = []

        async def probe(path: str) -> str | None:
            url = f"{base}{path}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as c:
                    r = await c.get(url)
                    if r.status_code not in (404, 405, 410):
                        return url
            except Exception:
                pass
            return None

        tasks = [probe(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                found.append(r)

        self.discovered_endpoints.extend(found)
        return found

    async def discover_params(
        self,
        url: str,
        wordlist: list[str] | None = None,
        max_params: int = 30,
    ) -> list[str]:
        """Fuzz for hidden/undocumented parameters."""
        params = (wordlist or COMMON_PARAMS)[:max_params]
        found: list[str] = []

        async def test_param(param: str) -> str | None:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}=test"
            base_url = url.split("?")[0]
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as c:
                    r_base = await c.get(base_url)
                    r_test = await c.get(test_url)
                    if len(r_test.content) != len(r_base.content):
                        return param
                    if r_test.status_code != r_base.status_code:
                        return param
            except Exception:
                pass
            return None

        tasks = [test_param(p) for p in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                found.append(r)

        self.discovered_params.extend(found)
        return found

    async def discover_auth_endpoints(
        self,
        base_url: str,
    ) -> list[str]:
        """Discover authentication-related endpoints."""
        auth_paths = [
            "/login", "/logout", "/signin", "/signup", "/register",
            "/forgot-password", "/reset-password", "/change-password",
            "/oauth/authorize", "/oauth/token", "/oauth/revoke",
            "/token/refresh", "/auth/login", "/auth/register",
            "/api/auth/login", "/api/auth/register",
            "/v1/auth/login", "/v2/auth/login",
        ]
        return await self.discover_endpoints(base_url, auth_paths, max_paths=len(auth_paths))

    def to_requestspecs(self) -> list[RequestSpec]:
        """Convert discovered endpoints to RequestSpecs for the engine."""
        specs = []
        for ep in self.discovered_endpoints:
            specs.append(RequestSpec(url=ep, method="GET").normalised())
        return specs
