"""Optional FastAPI service surface over the screening pipeline.

Importing this module requires FastAPI; the test suite skips the API
tests when it is absent, and the pure-stdlib CLI path always works.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .audit import AuditLog
from .config import Settings
from .eval import run_eval
from .pipeline import ScreeningPipeline


class ScreenRequest(BaseModel):
    text: str = Field(..., min_length=1)
    tenant: str = "default"
    pack: str = "default"


class ScreenResponse(BaseModel):
    action: str
    sanitized_text: str
    risk_score: float
    risk_band: str
    rule_name: str | None
    reasons: list[str]
    findings: list[dict]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="ai-guardrails-layer",
                  description="PII / policy / jailbreak screening as a service")
    audit = AuditLog(settings.audit_log_path) if settings.audit_enabled else None
    pipelines = {name: ScreeningPipeline(name, audit_log=audit)
                 for name in ("default", "strict", "permissive")}

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "packs": sorted(pipelines)}

    @app.post("/screen", response_model=ScreenResponse)
    def screen(req: ScreenRequest) -> ScreenResponse:
        pipeline = pipelines.get(req.pack) or pipelines[settings.default_pack]
        result = pipeline.screen(req.text, tenant=req.tenant)
        return ScreenResponse(
            action=result.action.value,
            sanitized_text=result.sanitized_text,
            risk_score=result.risk_score,
            risk_band=result.risk_band,
            rule_name=result.rule_name,
            reasons=result.reasons,
            findings=[{"kind": f.kind, "severity": f.severity.value,
                       "detail": f.detail, "score": round(f.score, 2)}
                      for f in result.findings],
        )

    @app.post("/eval")
    def eval_endpoint() -> dict:
        return run_eval().to_dict()

    return app


app = create_app()
