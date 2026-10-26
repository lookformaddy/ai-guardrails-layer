"""PII and secret detectors plus masking/redaction.

Pure-stdlib, regex-based detectors. They are deliberately pattern-based
rather than model-based: deterministic, explainable, and fast enough to
run synchronously in front of every model call. Each detector returns
:class:`Finding` objects with character spans so redaction can replace
exactly the sensitive substring.

A note on scope: these patterns detect *shapes* of sensitive data
(SSN-like, card-like). A card-shaped number is only flagged as a credit
card when it also passes the Luhn checksum, which keeps dates, order
numbers, and other digit runs out of the results.
"""

from __future__ import annotations

import re

from .models import Finding, Severity

# Placeholder tokens used when masking. They keep the *shape* of the
# redaction visible to downstream reviewers without leaking the value.
REDACTION_TOKEN = {
    "pii.email": "[REDACTED:EMAIL]",
    "pii.phone": "[REDACTED:PHONE]",
    "pii.ssn": "[REDACTED:SSN]",
    "pii.credit_card": "[REDACTED:CARD]",
    "pii.api_key": "[REDACTED:API_KEY]",
    "pii.secret": "[REDACTED:SECRET]",
    "pii.private_key": "[REDACTED:PRIVATE_KEY]",
}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0 and len(digits) >= 13


# Each entry: (kind, severity, compiled pattern, validator-or-None)
_PATTERNS: list[tuple[str, Severity, re.Pattern[str], object]] = [
    (
        "pii.email",
        Severity.MEDIUM,
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        None,
    ),
    (
        "pii.phone",
        Severity.MEDIUM,
        re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s])\d{3}[-.\s]\d{4}(?!\d)"
        ),
        None,
    ),
    (
        "pii.ssn",
        Severity.HIGH,
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        None,
    ),
    (
        "pii.credit_card",
        Severity.HIGH,
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        lambda m: _luhn_ok(re.sub(r"\D", "", m)),
    ),
    (
        # Generic API-key shapes: long token after a key-ish label, or a
        # well-known vendor prefix. No vendor SDKs are imported; these
        # are plain shapes.
        "pii.api_key",
        Severity.HIGH,
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9_\-]{20,})['\"]?"
            r"|sk-[A-Za-z0-9]{16,}"
            r"|AKIA[0-9A-Z]{16}"
            r"|ghp_[A-Za-z0-9]{20,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
        ),
        None,
    ),
    (
        "pii.secret",
        Severity.HIGH,
        re.compile(
            r"(?i)(?:password|passwd|secret|client[_-]?secret)\s*[:=]\s*"
            r"['\"][^'\"]{4,}['\"]"
        ),
        None,
    ),
    (
        "pii.private_key",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        None,
    ),
]


def detect_pii(text: str) -> list[Finding]:
    """Return all PII/secret findings in ``text``, sorted by span."""
    findings: list[Finding] = []
    for kind, severity, pattern, validator in _PATTERNS:
        for match in pattern.finditer(text):
            if validator is not None and not validator(match.group(0)):
                continue
            findings.append(
                Finding(
                    kind=kind,
                    severity=severity,
                    span=(match.start(), match.end()),
                    matched_text=match.group(0),
                    detail=f"Pattern match for {kind}",
                    score=SEVERITY_SCORE[severity],
                )
            )
    findings.sort(key=lambda f: (f.span[0], f.span[1]))
    return _dedupe_overlaps(findings)


SEVERITY_SCORE = {
    Severity.LOW: 10.0,
    Severity.MEDIUM: 30.0,
    Severity.HIGH: 60.0,
    Severity.CRITICAL: 90.0,
}


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    """Drop a finding fully contained in an earlier, longer finding."""
    kept: list[Finding] = []
    for f in findings:
        if any(k.span[0] <= f.span[0] and f.span[1] <= k.span[1]
               for k in kept):
            continue
        kept.append(f)
    return kept


def redact(text: str, findings: list[Finding],
           kinds: set[str] | None = None) -> str:
    """Replace each finding's span with its redaction token.

    ``kinds`` optionally restricts redaction to a subset (e.g. only PII,
    leaving injection markers visible for review). Spans are applied
    right-to-left so earlier offsets stay valid.
    """
    targets = [f for f in findings
               if kinds is None or f.kind in kinds or
               any(f.kind.startswith(k + ".") for k in kinds)]
    out = text
    for f in sorted(targets, key=lambda x: x.span[0], reverse=True):
        token = REDACTION_TOKEN.get(f.kind, "[REDACTED]")
        out = out[: f.span[0]] + token + out[f.span[1]:]
    return out


def pii_kinds(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind.startswith("pii.")]
