from __future__ import annotations

import re
from typing import Any

REDACTION = "[REDACTED]"

_TEXT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)([?&](?:token|access_token|api_key|key|secret)=)[^&#\s]+"),
]

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "auth_token",
    "bearer",
    "client_secret",
    "password",
    "passwd",
    "private_key",
    "secret",
    "secret_key",
    "token",
}


def redact_text(text: str) -> str:
    redacted = text
    for pattern in _TEXT_PATTERNS:
        if pattern.pattern.startswith("(?i)([?&]"):
            redacted = pattern.sub(lambda match: f"{match.group(1)}{REDACTION}", redacted)
        else:
            redacted = pattern.sub(REDACTION, redacted)
    return redacted


def _key_is_sensitive(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or any(part in normalized for part in ("password", "secret", "token"))


def redact_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTION if _key_is_sensitive(str(key)) else redact_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
