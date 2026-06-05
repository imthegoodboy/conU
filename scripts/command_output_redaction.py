"""Redaction helpers for subprocess failure output."""

from __future__ import annotations

import re


REDACTED = "[redacted]"
SECRET_NAME_PATTERN = (
    r"TOKEN|SECRET|PASSWORD|PASSWD|AUTH|"
    r"PRIVATE[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|API[_-]?KEY|"
    r"SECURITY[_-]?TOKEN|SESSION[_-]?TOKEN"
)
SECRET_VALUE_PATTERN = r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
SECRET_ASSIGNMENT_RE = re.compile(
    rf"\b([A-Z0-9_.-]*(?:{SECRET_NAME_PATTERN})"
    rf"[A-Z0-9_.-]*)\s*([=:])\s*{SECRET_VALUE_PATTERN}",
    re.IGNORECASE,
)
AUTH_HEADER_RE = re.compile(r"\b(Bearer|Basic)\s+([A-Za-z0-9._~+/\-=]{8,})", re.IGNORECASE)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]*PRIVATE KEY(?: BLOCK)?-----"
    r".*?"
    r"-----END [A-Z0-9 _-]*PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE | re.DOTALL,
)
SECRET_FLAG_RE = re.compile(
    rf"(?<!\w)(-{{1,2}}[A-Z0-9_.-]*(?:{SECRET_NAME_PATTERN})"
    r"[A-Z0-9_.-]*)(\s*=\s*|\s+)"
    rf"{SECRET_VALUE_PATTERN}",
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
SAFE_BOOLEAN_GUARD_ASSIGNMENTS = (
    "alertBodiesDisplayed=false",
    "checksumTargetDisplayed=false",
    "ciphertextDisplayed=false",
    "commandOutputDisplayed=false",
    "contentsDisplayed=false",
    "endpointDisplayed=false",
    "keyContentsDisplayed=false",
    "keyMaterialDisplayed=false",
    "pathDisplayed=false",
    "payloadDisplayed=false",
    "secretValuesDisplayed=false",
    "sessionIdDisplayed=false",
    "signatureContentsDisplayed=false",
    "statePathDisplayed=false",
    "tokenDisplayed=false",
    "tokenHashDisplayed=false",
)
DISPLAY_GUARD_NAMES = tuple(
    assignment.removesuffix("=false") for assignment in SAFE_BOOLEAN_GUARD_ASSIGNMENTS
)
DISPLAY_GUARD_ASSIGNMENT_RE = re.compile(
    r"\b("
    + "|".join(re.escape(name) for name in DISPLAY_GUARD_NAMES)
    + r")\s*([=:])\s*([^\s;&|]+)"
)


def redact_command_output(value: str) -> str:
    value, protected_guards = protect_safe_boolean_guards(value)
    value = PRIVATE_KEY_BLOCK_RE.sub(REDACTED, value)
    value = URL_CREDENTIAL_RE.sub(r"\1\2:[redacted]@", value)
    value = URL_SECRET_QUERY_RE.sub(r"\1[redacted]", value)
    value = AUTH_HEADER_RE.sub(r"\1 [redacted]", value)
    value = SECRET_FLAG_RE.sub(r"\1\2[redacted]", value)
    value = NPM_TOKEN_RE.sub(REDACTED, value)
    value = GITHUB_TOKEN_RE.sub(REDACTED, value)
    value = DISPLAY_GUARD_ASSIGNMENT_RE.sub(r"\1\2[redacted]", value)
    value = SECRET_ASSIGNMENT_RE.sub(r"\1\2[redacted]", value)
    value = restore_safe_boolean_guards(value, protected_guards)
    return value


def protect_safe_boolean_guards(value: str) -> tuple[str, dict[str, str]]:
    replacements: dict[str, str] = {}
    for index, assignment in enumerate(SAFE_BOOLEAN_GUARD_ASSIGNMENTS):
        placeholder = f"__CONU_SAFE_GUARD_{index}__"
        if assignment in value:
            value = value.replace(assignment, placeholder)
            replacements[placeholder] = assignment
    return value, replacements


def restore_safe_boolean_guards(value: str, replacements: dict[str, str]) -> str:
    for placeholder, assignment in replacements.items():
        value = value.replace(placeholder, assignment)
    return value
