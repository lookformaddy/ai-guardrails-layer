"""ai-guardrails-layer: PII / policy / jailbreak screening as a service.

Pure-stdlib core (detectors, policy engine, scoring, audit, eval).
The FastAPI surface in :mod:`guardrails.service` is optional.
"""

from .audit import AuditLog
from .eval import GOLDEN_CASES, run_eval
from .models import Action, Finding, PolicyPack, PolicyRule, ScreenResult, Severity
from .pipeline import ScreeningPipeline
from .policy import BUILTIN_PACKS

__all__ = [
    "Action", "AuditLog", "BUILTIN_PACKS", "Finding", "GOLDEN_CASES",
    "PolicyPack", "PolicyRule", "ScreenResult", "ScreeningPipeline",
    "Severity", "run_eval",
]

__version__ = "1.0.0"
