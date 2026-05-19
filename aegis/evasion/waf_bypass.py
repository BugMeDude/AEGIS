"""WAF detection and payload mutation for bypass."""

from __future__ import annotations

import base64
import random
import re
import string
from typing import Any

WAF_PATTERNS: dict[str, list[re.Pattern]] = {
    "Cloudflare": [re.compile(r"cloudflare|__cfduid|cf-ray", re.I)],
    "AWS WAF": [re.compile(r"awswaf|x-amzn-requestid", re.I)],
    "ModSecurity": [re.compile(r"mod_security|NOYB", re.I)],
    "Akamai": [re.compile(r"akamai|x-akamai", re.I)],
    "F5 BIG-IP": [re.compile(r"big-ip|tsession|BIGIP", re.I)],
    "Imperva": [re.compile(r"incapsula|imperva", re.I)],
    "Sucuri": [re.compile(r"sucuri|x-sucuri", re.I)],
    "Fortinet": [re.compile(r"fortigate|fortiweb", re.I)],
    "CloudFront": [re.compile(r"cloudfront|x-amz-cf", re.I)],
    "Generic": [re.compile(r"blocked|denied|rejected|forbidden", re.I)],
}

MUTATION_TECHNIQUES = [
    "case_permutation",
    "url_encoding",
    "double_url_encoding",
    "unicode_normalization",
    "comment_injection",
    "whitespace_variation",
    "parameter_pollution",
    "null_byte_injection",
    "base64_encoding",
    "hex_encoding",
    "chunked_transfer",
    "multipart_mixed",
]


class WAFDetector:
    """Detect WAF presence and type from HTTP responses."""

    @staticmethod
    def detect(headers: dict[str, str], body: str = "",
               status_code: int = 0) -> dict[str, Any]:
        """Detect WAF from response characteristics.

        Returns dict with 'detected', 'name', 'confidence', 'indicators'.
        """
        h = {k.lower(): v for k, v in headers.items()}
        all_text = str(h) + body.lower()
        indicators: list[str] = []

        for waf_name, patterns in WAF_PATTERNS.items():
            for p in patterns:
                if p.search(all_text):
                    indicators.append(waf_name)
                    return {
                        "detected": True,
                        "name": waf_name,
                        "confidence": 0.8 if status_code in (403, 406, 503) else 0.5,
                        "indicators": indicators,
                    }

        if status_code in (403, 406):
            indicators.append("403/406 on test payload")
            return {
                "detected": True,
                "name": "Unknown WAF",
                "confidence": 0.4,
                "indicators": indicators,
            }

        if status_code == 503 and "retry-after" in h:
            indicators.append("503 rate-limited")
            return {
                "detected": True,
                "name": "Rate-limiting WAF",
                "confidence": 0.6,
                "indicators": indicators,
            }

        return {"detected": False, "name": "", "confidence": 0.0, "indicators": []}


class PayloadMutator:
    """Apply various encoding/obfuscation techniques to payloads."""

    @staticmethod
    def mutate(payload: str, technique: str = "auto",
               vuln_class: str = "sqli") -> str:
        """Apply a mutation technique to a payload.

        Args:
            payload: The original payload string
            technique: Specific technique or 'auto' for random selection
            vuln_class: Vulnerability class for context-aware mutation

        Returns:
            Mutated payload string
        """
        if technique == "auto":
            technique = random.choice(MUTATION_TECHNIQUES)

        mutators = {
            "case_permutation": lambda p: PayloadMutator._case_permutation(p, vuln_class),
            "url_encoding": lambda p: PayloadMutator._url_encode(p),
            "double_url_encoding": lambda p: PayloadMutator._double_url_encode(p),
            "unicode_normalization": lambda p: PayloadMutator._unicode_normalize(p),
            "comment_injection": lambda p: PayloadMutator._inject_comments(p, vuln_class),
            "whitespace_variation": lambda p: PayloadMutator._vary_whitespace(p),
            "parameter_pollution": lambda p: PayloadMutator._param_pollution(p),
            "null_byte_injection": lambda p: p + "%00",
            "base64_encoding": lambda p: PayloadMutator._base64_wrap(p, vuln_class),
            "hex_encoding": lambda p: PayloadMutator._hex_encode(p),
            "chunked_transfer": lambda p: p,  # applied at transport level
            "multipart_mixed": lambda p: p,  # applied at transport level
        }

        mutator = mutators.get(technique, lambda p: p)
        return mutator(payload)

    @staticmethod
    def _case_permutation(payload: str, vuln_class: str) -> str:
        """Randomize case of SQL keywords or non-critical characters."""
        if vuln_class == "sqli":
            keywords = {"select", "union", "from", "where", "or", "and",
                        "sleep", "insert", "update", "delete", "drop"}
            result = []
            for word in payload.split():
                cleaned = word.strip("'\"()=;")
                if cleaned.lower() in keywords:
                    mutated = "".join(
                        c.upper() if random.random() > 0.5 else c.lower()
                        for c in word
                    )
                    result.append(mutated)
                else:
                    result.append(word)
            return " ".join(result)
        return payload

    @staticmethod
    def _url_encode(payload: str) -> str:
        """URL-encode special characters."""
        result = []
        for c in payload:
            if c in "<>'\"();|&$`{}[]!@#":
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL-encode."""
        single = PayloadMutator._url_encode(payload)
        return PayloadMutator._url_encode(single)

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Use unicode normalization variants."""
        replacements = {
            "'": ["\u2018", "\u2019", "\u02BB", "\u02BC"],
            '"': ["\u201C", "\u201D", "\u02BA"],
            '<': ["\u2039", "\u2329"],
            '>': ["\u203A", "\u232A"],
            '(': ["\u207D", "\u208D"],
            ')': ["\u207E", "\u208E"],
        }
        result = list(payload)
        for i, c in enumerate(result):
            if c in replacements:
                result[i] = random.choice(replacements[c])
        return "".join(result)

    @staticmethod
    def _inject_comments(payload: str, vuln_class: str) -> str:
        """Inject inline comments into SQL keywords."""
        if vuln_class == "sqli":
            # MySQL comment injection: SE/**/LECT
            result = []
            for word in payload.split():
                cleaned = word.strip("'\"()=;")
                if cleaned.lower() in ("select", "union", "from", "where",
                                       "or", "and", "sleep", "insert"):
                    mid = len(word) // 2
                    result.append(f"{word[:mid]}/**/{word[mid:]}")
                else:
                    result.append(word)
            return " ".join(result)
        return payload

    @staticmethod
    def _vary_whitespace(payload: str) -> str:
        """Replace spaces with tab, newline, or comment blocks."""
        whitespace_variants = ["\t", "\n", "/**/", "/*!*/"]
        result = []
        for word in payload.split():
            result.append(word)
            result.append(random.choice(whitespace_variants))
        return "".join(result[:-1]) if result else payload

    @staticmethod
    def _param_pollution(payload: str) -> str:
        """Add duplicate parameter for HTTP parameter pollution."""
        return payload + "&q=" + payload

    @staticmethod
    def _base64_wrap(payload: str, vuln_class: str) -> str:
        """Base64 encode payload for WAF bypass (if target decodes)."""
        encoded = base64.b64encode(payload.encode()).decode()
        if vuln_class in ("sqli", "cmdi"):
            return f"' UNION SELECT {encoded}-- "
        return encoded

    @staticmethod
    def _hex_encode(payload: str) -> str:
        """Hex encode the payload."""
        return "0x" + payload.encode().hex()

    @staticmethod
    def evolve(payloads: list[str], block_signature: str = "",
               vuln_class: str = "sqli") -> list[str]:
        """Generate multiple mutated variants of payloads."""
        evolved = []
        for p in payloads:
            for technique in MUTATION_TECHNIQUES[:6]:
                evolved.append(PayloadMutator.mutate(p, technique, vuln_class))
        return evolved[:20]
