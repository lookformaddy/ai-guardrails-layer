"""Shared data models for the guardrails screening pipeline.

All models are plain dataclasses so the core stays dependency-free and
trivially serialisable to the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    """What the policy engine decides for a screened request."""

    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    FLAG = "FLAG"


class Severity(str, Enum):
    """Severity attached to a single detector finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.LOW: 10.0,
    Severity.MEDIUM: 30.0,
    Severity.HIGH: 60.0,
    Severity.CRITICAL: 90.0,
}


@dataclass(frozen=True)
class Finding:
    """One detector hit inside a screened text."""

    kind: str  # e.g. "pii.email", "injection.instruction_override"
    severity: Severity
    span: tuple[int, int]  # (start, end) offsets into the original text
    matched_text: str
    detail: str = ""
    score: float = 0.0  # detector-local confidence / severity score, 0-100


@dataclass
class ScreenResult:
    """Outcome of one full pipeline run."""

    action: Action
    original_text: str
    sanitized_text: str
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    risk_band: str = "LOW"
    reasons: list[str] = field(default_factory=list)
    rule_name: str | None = None
    tenant: str = "default"
    request_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "tenant": self.tenant,
            "request_id": self.request_id,
            "risk_score": round(self.risk_score, 2),
            "risk_band": self.risk_band,
            "rule_name": self.rule_name,
            "reasons": list(self.reasons),
            "findings": [
                {
                    "kind": f.kind,
                    "severity": f.severity.value,
                    "span": list(f.span),
                    "matched_text": f.matched_text,
                    "detail": f.detail,
                    "score": round(f.score, 2),
                }
                for f in self.findings
            ],
            "sanitized_text": self.sanitized_text,
        }


@dataclass(frozen=True)
class PolicyRule:
    """One ordered policy rule. First matching rule wins.

    A rule matches when every non-None criterion matches:
    - ``kinds``: finding kind prefix or exact kind (prefix match, so
      "pii" matches "pii.email").
    - ``min_severity``: at least one matching finding at this severity.
    - ``min_risk_score``: the aggregate risk score meets the threshold.
    - ``tenant``: only applies to this tenant (None = any tenant).
    """

    name: str
    action: Action
    kinds: tuple[str, ...] = ()
    min_severity: Severity | None = None
    min_risk_score: float | None = None
    tenant: str | None = None
    reason: str = ""

    def matches(self, findings: list[Finding], risk_score: float,
                tenant: str) -> bool:
        if self.tenant is not None and self.tenant != tenant:
            return False
        if self.min_risk_score is not None and risk_score < self.min_risk_score:
            return False
        if not self.kinds and self.min_severity is None:
            return True  # catch-all rule
        matched = findings
        if self.kinds:
            matched = [f for f in matched
                       if any(f.kind == k or f.kind.startswith(k + ".")
                              for k in self.kinds)]
        if self.min_severity is not None:
            order = list(Severity)
            matched = [f for f in matched
                       if order.index(f.severity) >= order.index(self.min_severity)]
        return bool(matched)


@dataclass
class PolicyPack:
    """An ordered rule list for one tenant / deployment."""

    name: str
    rules: list[PolicyRule] = field(default_factory=list)
    default_action: Action = Action.ALLOW

    def evaluate(self, findings: list[Finding], risk_score: float,
                 tenant: str) -> tuple[Action, str | None, str]:
        for rule in self.rules:
            if rule.matches(findings, risk_score, tenant):
                return rule.action, rule.name, rule.reason or rule.name
        return self.default_action, None, "default action"
