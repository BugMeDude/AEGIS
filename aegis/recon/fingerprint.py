"""Technology stack and WAF fingerprinting from HTTP responses.

Detects: web servers, frameworks, CMS platforms, WAFs, CDNs,
programming languages, and databases — based on response headers,
body patterns, and behavior.
"""

from __future__ import annotations

import re
from typing import Any

# ── Signature Databases ──────────────────────────────────────────────

SERVER_SIGNATURES: dict[str, list[re.Pattern]] = {
    "nginx": [re.compile(r"nginx", re.I)],
    "Apache": [re.compile(r"apache", re.I)],
    "IIS": [re.compile(r"microsoft-iis", re.I), re.compile(r"iis", re.I)],
    "Cloudflare": [re.compile(r"cloudflare", re.I)],
    "Caddy": [re.compile(r"caddy", re.I)],
    "OpenResty": [re.compile(r"openresty", re.I)],
    "Tomcat": [re.compile(r"tomcat", re.I), re.compile(r"apache-coyote", re.I)],
    "Jetty": [re.compile(r"jetty", re.I)],
    "Node.js": [re.compile(r"node\.?js", re.I), re.compile(r"express", re.I)],
    "Python": [re.compile(r"python|gunicorn|uwsgi|waitress|daphne", re.I)],
    "Ruby": [re.compile(r"ruby|phusion|passenger|puma|unicorn", re.I)],
    "Go": [re.compile(r"go|golang|fasthttp", re.I)],
    "Java": [re.compile(r"java|jdk|jre|spring|tomcat|jboss|wildfly|glassfish", re.I)],
}

WAF_SIGNATURES: dict[str, list[re.Pattern]] = {
    "Cloudflare": [re.compile(r"cloudflare", re.I),
                   re.compile(r"__cfduid", re.I),
                   re.compile(r"cf-ray", re.I)],
    "AWS WAF": [re.compile(r"awswaf", re.I),
                re.compile(r"x-amzn-requestid", re.I),
                re.compile(r"x-amzn-trace-id", re.I)],
    "ModSecurity": [re.compile(r"mod_security", re.I),
                    re.compile(r"NOYB", re.I)],
    "Akamai": [re.compile(r"akamai", re.I),
               re.compile(r"x-akamai", re.I)],
    "F5 BIG-IP": [re.compile(r"big-ip", re.I),
                  re.compile(r"tsession", re.I),
                  re.compile(r"BIGIP", re.I)],
    "Imperva": [re.compile(r"incapsula", re.I), re.compile(r"imperva", re.I)],
    "Sucuri": [re.compile(r"sucuri", re.I), re.compile(r"x-sucuri", re.I)],
    "Fortinet": [re.compile(r"fortigate|fortiweb", re.I)],
    "Cloudfront": [re.compile(r"cloudfront", re.I),
                   re.compile(r"x-amz-cf", re.I)],
    "CloudFlare": [re.compile(r"cloudflare", re.I)],
}

FRAMEWORK_SIGNATURES: dict[str, list[re.Pattern]] = {
    "Django": [re.compile(r"django", re.I), re.compile(r"csrftoken", re.I)],
    "Flask": [re.compile(r"flask", re.I)],
    "FastAPI": [re.compile(r"fastapi", re.I)],
    "Spring Boot": [re.compile(r"spring", re.I), re.compile(r"x-application-context", re.I)],
    "Rails": [re.compile(r"rails", re.I), re.compile(r"ruby on rails", re.I)],
    "Laravel": [re.compile(r"laravel", re.I)],
    "Symfony": [re.compile(r"symfony", re.I)],
    "ASP.NET": [re.compile(r"asp\.net", re.I), re.compile(r"x-aspnet", re.I)],
    "Next.js": [re.compile(r"next\.?js", re.I), re.compile(r"x-nextjs", re.I)],
    "Nuxt": [re.compile(r"nuxt", re.I)],
    "Gatsby": [re.compile(r"gatsby", re.I)],
    "WordPress": [re.compile(r"wordpress", re.I), re.compile(r"wp-", re.I)],
    "Drupal": [re.compile(r"drupal", re.I)],
    "Joomla": [re.compile(r"joomla", re.I)],
}

AUTH_SIGNATURES: dict[str, list[re.Pattern]] = {
    "JWT": [re.compile(r"jwt|json web token", re.I)],
    "OAuth2": [re.compile(r"oauth|bearer\s+[a-z0-9]", re.I)],
    "Basic Auth": [re.compile(r"basic\s+realm", re.I)],
    "API Key": [re.compile(r"x-api-key", re.I)],
    "Session Cookie": [re.compile(r"sessionid|session_id|connect.sid|PHPSESSID|JSESSIONID",
                                   re.I)],
}


class Fingerprinter:
    """Analyze HTTP response headers and body to identify technology stack."""

    def __init__(self) -> None:
        self.server: str = ""
        self.waf: str = ""
        self.framework: str = ""
        self.language: str = ""
        self.auth: str = ""
        self.cdn: str = ""
        self._confidence: dict[str, float] = {}

    def fingerprint(self, status: int, headers: dict[str, str],
                    body: str = "") -> dict[str, Any]:
        """Fingerprint a target from a single HTTP response.

        Returns a dict with detected technologies and confidence scores.
        """
        h = {k.lower(): v for k, v in headers.items()}
        low_body = body.lower()
        all_text = str(h) + low_body

        self.server = self._detect(h.get("server", ""), all_text, SERVER_SIGNATURES)
        self.waf = self._detect("", all_text, WAF_SIGNATURES)
        self.framework = self._detect("", all_text, FRAMEWORK_SIGNATURES)
        self.auth = self._detect("", all_text, AUTH_SIGNATURES)

        if "set-cookie" in h:
            for p in SERVER_SIGNATURES.get("Cloudflare", []):
                if p.search(h.get("set-cookie", "")):
                    self.cdn = "Cloudflare"
                    break

        if "via" in h:
            via = h["via"]
            for cdn_name, sigs in {
                "Cloudflare": [re.compile(r"cloudflare", re.I)],
                "Fastly": [re.compile(r"fastly", re.I)],
                "Akamai": [re.compile(r"akamai", re.I)],
                "CloudFront": [re.compile(r"cloudfront", re.I)],
            }.items():
                if any(s.search(via) for s in sigs):
                    self.cdn = cdn_name
                    break

        return {
            "server": self.server,
            "waf": self.waf,
            "framework": self.framework,
            "language": "python" if any(p.search(str(h)) for p in
                           SERVER_SIGNATURES.get("Python", [])) else "",
            "auth": self.auth,
            "cdn": self.cdn,
            "all_headers": dict(headers),
        }

    def _detect(self, target_text: str, full_text: str,
                signatures: dict[str, list[re.Pattern]]) -> str:
        for name, patterns in signatures.items():
            for p in patterns:
                if p.search(target_text) or p.search(full_text):
                    return name
        return ""
