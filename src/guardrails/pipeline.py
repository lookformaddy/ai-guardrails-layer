"""The screening pipeline: detectors -> risk score -> policy -> action.

Order matters and is deliberate:

1. **Detect** PII/secrets and injection signals (independent passes).
2. **Score** the combined findings into one 0–100 risk score.
3. **Decide** via the tenant's policy pack (first matching rule wins).
4. **Enforce**:
   - BLOCK — nothing is forwarded; sanitized text is empty, and the
     reason names the rule that fired.
   - REDACT — PII spans are replaced with tokens; injection findings
     are *not* edited out (editing an attacker's text can hide the
     attack from reviewers; the flagged original is preserved in the
     audit trail as finding metadata, never as raw text).
   - FLAG — text passes through unchanged, but the decision is
     recorded for review.
   - ALLOW — passes through unchanged.
5. **Audit** every decision, whatever the action.

The pipeline is fail-closed at the edges: a detector raising an
exception must not silently ALLOW traffic. :meth:`ScreeningPipeline.screen`
therefore catches detector errors, records them as a finding, and
escalates the decision to BLOCK.
"""

from __future__ import annotations

import itertools
import uuid

from .audit import AuditLog
from .injection import detect_injection
from .models import Action, Finding, ScreenResult, Severity
from .pii import detect_pii, pii_kinds, redact
from .policy import BUILTIN_PACKS
from .scoring import risk_band, risk_score


class ScreeningPipeline:
    """Stateless screening except for the optional audit log."""

    def __init__(self, pack_name: str = "default",
                 audit_log: AuditLog | None = None) -> None:
        if pack_name not in BUILTIN_PACKS:
            raise ValueError(f"Unknown policy pack: {pack_name!r}")
        self.pack_name = pack_name
        self.pack = BUILTIN_PACKS[pack_name]
        self.audit_log = audit_log
        self._counter = itertools.count(1)

    def screen(self, text: str, tenant: str = "default",
               request_id: str | None = None) -> ScreenResult:
        request_id = request_id or f"req-{next(self._counter):06d}-{uuid.uuid4().hex[:8]}"
        try:
            findings = detect_pii(text) + detect_injection(text)
            findings.sort(key=lambda f: (f.span[0], f.span[1]))
        except Exception as exc:  # fail closed: never ALLOW on detector failure
            findings = [Finding(
                kind="system.detector_error",
                severity=Severity.CRITICAL,
                span=(0, 0),
                matched_text="",
                detail=f"Detector failure: {exc}",
                score=100.0,
            )]
        score = risk_score(findings)
        action, rule_name, reason = self.pack.evaluate(findings, score, tenant)
        if action is Action.BLOCK:
            sanitized = ""
        elif action is Action.REDACT:
            sanitized = redact(text, pii_kinds(findings))
        else:
            sanitized = text
        reasons = [reason]
        if action is Action.BLOCK and rule_name is None:
            reasons = ["blocked by default action"]
        result = ScreenResult(
            action=action,
            original_text=text,
            sanitized_text=sanitized,
            findings=findings,
            risk_score=score,
            risk_band=risk_band(score),
            reasons=reasons,
            rule_name=rule_name,
            tenant=tenant,
            request_id=request_id,
        )
        if self.audit_log is not None:
            self.audit_log.append(result)
        return result
