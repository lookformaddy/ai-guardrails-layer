"""Command-line interface: screen text, run the eval, serve the API."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditLog
from .config import Settings
from .eval import run_eval
from .pipeline import ScreeningPipeline


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardrails",
                                     description="AI guardrails screening layer")
    sub = parser.add_subparsers(dest="command", required=True)

    screen = sub.add_parser("screen", help="Screen one text")
    screen.add_argument("text", help="Text to screen")
    screen.add_argument("--pack", default="default",
                        choices=("default", "strict", "permissive"))
    screen.add_argument("--tenant", default="default")
    screen.add_argument("--audit", default=None,
                        help="Path to append the decision to a JSONL audit log")

    sub.add_parser("eval", help="Run the synthetic golden-set eval")

    serve = sub.add_parser("serve", help="Serve the FastAPI API")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "screen":
        audit = AuditLog(args.audit) if args.audit else None
        result = ScreeningPipeline(args.pack, audit_log=audit).screen(
            args.text, tenant=args.tenant)
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.action.value != "BLOCK" else 2
    if args.command == "eval":
        print(json.dumps(run_eval().to_dict(), indent=2))
        return 0
    if args.command == "serve":
        settings = Settings.from_env()
        if args.host:
            settings.host = args.host
        if args.port:
            settings.port = args.port
        import uvicorn  # deferred: only needed for serve

        from .service import create_app

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
