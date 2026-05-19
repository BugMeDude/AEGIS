"""API schema extraction from OpenAPI, GraphQL introspection, and observation.

Discovers:
  - OpenAPI/Swagger specs from common paths
  - GraphQL schema via introspection queries
  - Parameter types from actual API responses
  - Authentication requirements per endpoint
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from ..models import RequestSpec

GRAPHQL_INTROSPECTION = """\
query {
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType { name kind }
          }
        }
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    directives { name description locations }
  }
}
"""


class SchemaExtractor:
    """Extract API schemas from various sources."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self.schema: dict[str, Any] = {}
        self.schema_type: str = ""  # openapi | graphql | observed
        self.endpoints: list[dict] = []
        self.params: dict[str, list[dict]] = {}

    async def extract_from_openapi(self, base_url: str) -> dict[str, Any] | None:
        """Attempt to find and parse OpenAPI/Swagger spec."""
        candidates = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/v2/api-docs", "/v3/api-docs",
            "/openapi.yaml", "/swagger.yaml",
            "/docs/json", "/api/swagger.json",
        ]
        base = base_url.rstrip("/")
        for path in candidates:
            url = f"{base}{path}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as c:
                    r = await c.get(url)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if "openapi" in data or "swagger" in data:
                                self.schema = data
                                self.schema_type = "openapi"
                                self._parse_openapi(data, base)
                                return data
                        except (json.JSONDecodeError, ValueError):
                            continue
            except Exception:
                continue
        return None

    async def extract_from_graphql(self, base_url: str) -> dict[str, Any] | None:
        """Attempt GraphQL introspection."""
        candidates = [
            "/graphql", "/api/graphql", "/v1/graphql", "/gql",
            "/query", "/api/query", "/graph",
        ]
        base = base_url.rstrip("/")
        for path in candidates:
            url = f"{base}{path}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as c:
                    r = await c.post(
                        url,
                        json={"query": GRAPHQL_INTROSPECTION},
                        headers={"Content-Type": "application/json"},
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if "data" in data and "__schema" in data.get("data", {}):
                            self.schema = data["data"]["__schema"]
                            self.schema_type = "graphql"
                            self._parse_graphql(data["data"]["__schema"], path)
                            return data
            except Exception:
                continue
        return None

    async def extract_from_response(
        self,
        spec: RequestSpec,
        response_body: str,
        response_headers: dict,
    ) -> dict[str, Any]:
        """Extract parameter types and schema from a real response."""
        info: dict[str, Any] = {
            "endpoint": spec.url,
            "method": spec.method,
            "content_type": response_headers.get("content-type", ""),
            "body_type": None,
            "params": [],
        }

        ct = response_headers.get("content-type", "").lower()
        if "json" in ct:
            try:
                parsed = json.loads(response_body)
                if isinstance(parsed, dict):
                    info["body_type"] = "json_object"
                    info["fields"] = list(parsed.keys())
                elif isinstance(parsed, list):
                    info["body_type"] = "json_array"
                    if parsed and isinstance(parsed[0], dict):
                        info["fields"] = list(parsed[0].keys())
            except (json.JSONDecodeError, ValueError):
                info["body_type"] = "text"
        elif "xml" in ct:
            info["body_type"] = "xml"
        elif "html" in ct:
            info["body_type"] = "html"
        else:
            info["body_type"] = "binary"

        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(spec.url).query)
        if qs:
            info["params"] = [{"name": k, "type": "query", "values": v} for k, v in qs.items()]

        self.endpoints.append(info)
        return info

    def _parse_openapi(self, data: dict, base_url: str) -> None:
        """Extract endpoints from OpenAPI spec."""
        paths = data.get("paths", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                ep_info = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": op.get("operationId", ""),
                    "summary": op.get("summary", ""),
                    "parameters": [],
                }
                for param in op.get("parameters", []):
                    ep_info["parameters"].append({
                        "name": param.get("name"),
                        "in": param.get("in"),
                        "required": param.get("required", False),
                        "type": param.get("schema", {}).get("type", "string"),
                    })
                self.endpoints.append(ep_info)

    def _parse_graphql(self, schema: dict, path: str) -> None:
        """Extract operations from GraphQL schema."""
        for t in schema.get("types", []):
            if t.get("name", "").startswith("__"):
                continue
            if t.get("fields"):
                for field in t.get("fields", []):
                    self.endpoints.append({
                        "path": path,
                        "type": t["name"],
                        "field": field.get("name"),
                        "args": [
                            {"name": a["name"], "type": a.get("type", {}).get("name", "unknown")}
                            for a in field.get("args", [])
                        ],
                    })

    def to_requestspecs(self) -> list[RequestSpec]:
        """Convert extracted schema to RequestSpecs for the engine."""
        specs = []
        if self.schema_type == "openapi":
            for ep in self.endpoints:
                url = urljoin(
                    self.schema.get("servers", [{}])[0].get("url", ""),
                    ep["path"],
                )
                specs.append(RequestSpec(url=url, method=ep["method"]).normalised())
        elif self.schema_type == "graphql":
            existing = set()
            for ep in self.endpoints:
                key = (ep.get("path", "/graphql"), "POST")
                if key not in existing:
                    existing.add(key)
                    specs.append(RequestSpec(url=f"{ep['path']}", method="POST",
                                             body='{"query": "{ __typename }"}',
                                             headers={"Content-Type": "application/json"}).normalised())
        return specs
