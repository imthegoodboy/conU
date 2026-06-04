"""Redaction helpers for subprocess failure output."""

from __future__ import annotations

import re


REDACTED = "[redacted]"
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b([A-Z0-9_.-]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|AUTH)"
    r"[A-Z0-9_.-]*)\s*([=:])\s*([^\s;&|]+)",
    re.IGNORECASE,
)
AUTH_HEADER_RE = re.compile(r"\b(Bearer|Basic)\s+([A-Za-z0-9._~+/\-=]{8,})", re.IGNORECASE)
SECRET_FLAG_RE = re.compile(
    r"(?<!\w)(-{1,2}[A-Z0-9_.-]*(?:"
    r"TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|AUTH|"
    r"ACCESS[_-]?KEY|SECRET[_-]?KEY|SECURITY[_-]?TOKEN|SESSION[_-]?TOKEN"
    r")[A-Z0-9_.-]*)(\s*=\s*|\s+)"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)",
    re.IGNORECASE,
)
NPM_TOKEN_RE = re.compile(r"\bnpm_[A-Za-z0-9]{10,}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}\b")
URL_CREDENTIAL_RE = re.compile(r"\b(https?://)([^/\s:@]+):([^@\s/]+)@", re.IGNORECASE)
URL_SECRET_QUERY_RE = re.compile(
    r"([?&](?:"
    r"token|access_token|auth|apikey|api_key|secret|password|pass|key|sig|"
    r"[A-Za-z0-9_.-]*(?:"
    r"credential|signature|signed|access[_-]?key|secret[_-]?key|"
    r"security[_-]?token|session[_-]?token"
    r")[A-Za-z0-9_.-]*"
    r")=)([^&#\s]+)",
    re.IGNORECASE,
)


def redact_command_output(value: str) -> str:
    value = URL_CREDENTIAL_RE.sub(r"\1\2:[redacted]@", value)
    value = URL_SECRET_QUERY_RE.sub(r"\1[redacted]", value)
    value = AUTH_HEADER_RE.sub(r"\1 [redacted]", value)
    value = SECRET_FLAG_RE.sub(r"\1\2[redacted]", value)
    value = NPM_TOKEN_RE.sub(REDACTED, value)
    value = GITHUB_TOKEN_RE.sub(REDACTED, value)
    value = SECRET_ASSIGNMENT_RE.sub(r"\1\2[redacted]", value)
    return value
