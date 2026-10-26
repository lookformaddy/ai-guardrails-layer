"""Environment-based configuration. No secrets are required to run:
the layer is fully local and model-agnostic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8000
    default_pack: str = "default"
    audit_log_path: str = "./data/audit.jsonl"
    audit_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            host=os.getenv("GUARDRAILS_HOST", "127.0.0.1"),
            port=int(os.getenv("GUARDRAILS_PORT", "8000")),
            default_pack=os.getenv("GUARDRAILS_PACK", "default"),
            audit_log_path=os.getenv("GUARDRAILS_AUDIT_PATH", "./data/audit.jsonl"),
            audit_enabled=os.getenv("GUARDRAILS_AUDIT_ENABLED", "true").lower()
            in ("1", "true", "yes"),
        )
