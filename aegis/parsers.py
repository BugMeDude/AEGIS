"""Input parsers: cURL, Postman v2.x, OpenAPI 3.x, HAR, and plain URL lists.

A big upgrade over the original ``ApiRequestHandler``: the cURL parser is a
real ``shlex`` tokeniser (handles ``--data-binary``, ``-u``, ``--compressed``,
``-G``, line continuations) and Postman collections are walked recursively
through folders with ``{{variable}}`` substitution.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any
from urllib.parse import urlencode

from .models import RequestSpec


# --------------------------------------------------------------------------- #
# cURL
# --------------------------------------------------------------------------- #
def parse_curl(command: str, variables: dict[str, str] | None = None) -> RequestSpec | None:
    """Parse a single ``curl`` command into a :class:`RequestSpec`."""
    variables = variables or {}
    command = command.strip()
    # Join shell line-continuations.
    command = re.sub(r"\\\s*\n", " ", command)
    command = command.replace("\n", " ").strip()
    if not command.startswith("curl"):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        # Fall back to a forgiving split if quoting is broken.
        tokens = command.split()
    if not tokens or tokens[0] != "curl":
        return None

    spec = RequestSpec(url="", method="", headers={})
    data_parts: list[str] = []
    get_form = False
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--request"):
            i += 1
            if i < len(tokens):
                spec.method = tokens[i].upper()
        elif t in ("-H", "--header"):
            i += 1
            if i < len(tokens) and ":" in tokens[i]:
                k, v = tokens[i].split(":", 1)
                spec.headers[k.strip()] = v.strip()
        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            i += 1
            if i < len(tokens):
                data_parts.append(tokens[i])
        elif t in ("--data-urlencode",):
            i += 1
            if i < len(tokens):
                data_parts.append(tokens[i])
        elif t in ("-u", "--user"):
            i += 1
            if i < len(tokens):
                import base64

                spec.headers["Authorization"] = "Basic " + base64.b64encode(
                    tokens[i].encode()
                ).decode()
        elif t in ("-G", "--get"):
            get_form = True
        elif t in ("-A", "--user-agent"):
            i += 1
            if i < len(tokens):
                spec.headers["User-Agent"] = tokens[i]
        elif t in ("-e", "--referer"):
            i += 1
            if i < len(tokens):
                spec.headers["Referer"] = tokens[i]
        elif t in ("-b", "--cookie"):
            i += 1
            if i < len(tokens):
                spec.headers["Cookie"] = tokens[i]
        elif t in ("--compressed", "-k", "--insecure", "-s", "-L",
                   "--location", "-i", "-v", "--silent", "-f", "--fail"):
            pass  # benign flags, ignore
        elif t.startswith("http://") or t.startswith("https://"):
            spec.url = t
        elif not t.startswith("-") and not spec.url:
            spec.url = t
        i += 1

    if not spec.url:
        return None

    body = "&".join(data_parts) if data_parts else None
    if body and get_form:
        sep = "&" if "?" in spec.url else "?"
        spec.url = f"{spec.url}{sep}{body}"
        body = None
    spec.body = body
    if not spec.method:
        spec.method = "POST" if body else "GET"

    _apply_vars(spec, variables)
    return spec.normalised()


def parse_curl_multi(text: str, variables: dict[str, str] | None = None) -> list[RequestSpec]:
    """Parse a blob possibly containing many ``curl`` commands."""
    blocks = re.split(r"(?=^\s*curl\b)", text, flags=re.MULTILINE)
    out: list[RequestSpec] = []
    for b in blocks:
        b = b.strip()
        if not b.startswith("curl"):
            continue
        spec = parse_curl(b, variables)
        if spec:
            out.append(spec)
    return out


# --------------------------------------------------------------------------- #
# Postman v2.x
# --------------------------------------------------------------------------- #
def _pm_subst(s: str, env: dict[str, str]) -> str:
    return re.sub(r"\{\{(\w+)\}\}", lambda m: env.get(m.group(1), m.group(0)), s or "")


def parse_postman(data: dict[str, Any], variables: dict[str, str] | None = None) -> list[RequestSpec]:
    env: dict[str, str] = {}
    for v in data.get("variable", []) or []:
        if isinstance(v, dict) and "key" in v:
            env[v["key"]] = str(v.get("value", ""))
    env.update(variables or {})

    out: list[RequestSpec] = []

    def walk(items: list[dict[str, Any]]) -> None:
        for item in items or []:
            if "item" in item:  # folder
                walk(item["item"])
                continue
            req = item.get("request")
            if not req:
                continue
            if isinstance(req, str):  # shorthand
                out.append(RequestSpec(url=_pm_subst(req, env)).normalised())
                continue
            spec = RequestSpec(url="", method=req.get("method", "GET"),
                               name=item.get("name", ""))
            url = req.get("url", "")
            if isinstance(url, dict):
                raw = url.get("raw") or ""
                if not raw and url.get("host"):
                    host = ".".join(url["host"]) if isinstance(url["host"], list) else url["host"]
                    path = "/".join(url.get("path", []) or [])
                    raw = f"{url.get('protocol', 'https')}://{host}/{path}"
                url = raw
            spec.url = _pm_subst(str(url), env)
            for h in req.get("header", []) or []:
                if isinstance(h, dict) and not h.get("disabled"):
                    spec.headers[_pm_subst(h.get("key", ""), env)] = _pm_subst(
                        str(h.get("value", "")), env
                    )
            body = req.get("body") or {}
            mode = body.get("mode")
            if mode == "raw":
                spec.body = _pm_subst(body.get("raw", ""), env)
            elif mode == "urlencoded":
                spec.body = urlencode(
                    {p["key"]: _pm_subst(str(p.get("value", "")), env)
                     for p in body.get("urlencoded", []) if not p.get("disabled")}
                )
            if spec.url:
                out.append(spec.normalised())

    walk(data.get("item", []))
    return out


# --------------------------------------------------------------------------- #
# OpenAPI 3.x / Swagger 2.0
# --------------------------------------------------------------------------- #
def parse_openapi(data: dict[str, Any], base_url: str = "") -> list[RequestSpec]:
    servers = data.get("servers") or []
    base = base_url or (servers[0]["url"] if servers else "")
    if not base and "host" in data:  # swagger 2.0
        scheme = (data.get("schemes") or ["https"])[0]
        base = f"{scheme}://{data['host']}{data.get('basePath', '')}"
    base = base.rstrip("/")

    out: list[RequestSpec] = []
    for path, methods in (data.get("paths") or {}).items():
        for method, op in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue
            spec = RequestSpec(
                url=f"{base}{path}",
                method=method.upper(),
                name=op.get("operationId") or f"{method.upper()} {path}",
            )
            if method.upper() in ("POST", "PUT", "PATCH"):
                spec.headers["Content-Type"] = "application/json"
                spec.body = "{}"
            out.append(spec.normalised())
    return out


# --------------------------------------------------------------------------- #
# HAR
# --------------------------------------------------------------------------- #
def parse_har(data: dict[str, Any]) -> list[RequestSpec]:
    out: list[RequestSpec] = []
    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        spec = RequestSpec(url=req.get("url", ""), method=req.get("method", "GET"))
        for h in req.get("headers", []):
            name = h.get("name", "")
            if name and not name.startswith(":"):
                spec.headers[name] = h.get("value", "")
        pd = req.get("postData")
        if pd:
            spec.body = pd.get("text")
        if spec.url:
            out.append(spec.normalised())
    return out


# --------------------------------------------------------------------------- #
# Auto-detect / dispatch
# --------------------------------------------------------------------------- #
def _apply_vars(spec: RequestSpec, variables: dict[str, str]) -> None:
    for k, v in variables.items():
        spec.url = spec.url.replace(f"{{{{{k}}}}}", v)


def parse_any(
    text: str,
    *,
    input_type: str = "auto",
    base_url: str = "",
    token: str = "",
    variables: dict[str, str] | None = None,
) -> list[RequestSpec]:
    """Parse arbitrary input. ``input_type`` ∈ auto|curl|postman|openapi|har|url."""
    text = (text or "").strip()
    variables = variables or {}
    specs: list[RequestSpec] = []

    if input_type == "auto":
        if text.startswith("curl"):
            input_type = "curl"
        elif text.startswith("{") or text.startswith("["):
            try:
                doc = json.loads(text)
                if "log" in doc and "entries" in doc.get("log", {}):
                    input_type = "har"
                elif "openapi" in doc or "swagger" in doc:
                    input_type = "openapi"
                elif "item" in doc or "info" in doc:
                    input_type = "postman"
                else:
                    input_type = "postman"
            except json.JSONDecodeError:
                input_type = "url"
        elif re.match(r"^https?://", text):
            input_type = "url"
        else:
            input_type = "curl"

    if input_type == "curl":
        specs = parse_curl_multi(text, variables)
    elif input_type == "url":
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"^https?://", line):
                specs.append(RequestSpec(url=line).normalised())
    else:
        doc = json.loads(text)
        if input_type == "postman":
            specs = parse_postman(doc, variables)
        elif input_type == "openapi":
            specs = parse_openapi(doc, base_url)
        elif input_type == "har":
            specs = parse_har(doc)

    # Global overrides.
    for s in specs:
        if base_url and input_type != "openapi":
            s.url = _swap_base(s.url, base_url)
        if token:
            s.headers["Authorization"] = (
                token if token.lower().startswith("bearer") else f"Bearer {token}"
            )
        for k, v in variables.items():
            if k not in ("base_url", "token"):
                s.headers.setdefault(k, v)
    return specs


def _swap_base(url: str, base: str) -> str:
    try:
        from urllib.parse import urlparse

        p = urlparse(url)
        rest = url.split(f"{p.scheme}://{p.netloc}", 1)
        tail = rest[1] if len(rest) > 1 else ""
        return base.rstrip("/") + tail
    except Exception:
        return url
