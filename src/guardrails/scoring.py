"""Risk scoring: combine detector findings into one 0–100 score.

Design:
- Each finding contributes its detector score, weighted by family:
  injection findings count at full weight (they signal intent),
  PII findings at half weight (they signal exposure, not malice).
- Stacking matters: repeated signals of the same family add up, but
  with diminishing returns (each additional finding contributes 70% of
  the previous one's contribution) so a long benign text with many
  phone numbers cannot out-score a genuine jailbreak.
- The result is capped at 100 and mapped to a band: LOW < 30,
  MEDIUM 30–69, HIGH >= 70.
"""

from __future__ import annotations

from .models import Finding

_FAMILY_WEIGHT = {
    "injection": 1.0,
    "pii": 0.5,
}

_DIMINISH = 0.7


def risk_score(findings: list[Finding]) -> float:
    by_family: dict[str, list[float]] = {}
    for f in findings:
        family = f.kind.split(".", 1)[0]
        by_family.setdefault(family, []).append(f.score)
    total = 0.0
    for family, scores in by_family.items():
        weight = _FAMILY_WEIGHT.get(family, 0.5)
        contribution = 0.0
        decay = 1.0
        for score in sorted(scores, reverse=True):
            contribution += score * decay
            decay *= _DIMINISH
        total += contribution * weight
    return min(100.0, round(total, 2))


def risk_band(score: float) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
