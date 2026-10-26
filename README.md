# ai-guardrails-layer

Every LLM call in an enterprise is a trust boundary: user input can
carry PII, secrets, or an instruction-injection attack aimed at the
model behind it, and model output can leak what it should not. This
project is the layer that sits in front of (and behind) those calls —
a **PII / policy / jailbreak screening service** that decides, per
request, whether to ALLOW, REDACT, BLOCK, or FLAG traffic, and records
every decision in a tamper-evident audit log.

**Track:** AI Engineering · enterprise portfolio series.

Built clean-room: all code is original, all demo data is synthetic,
and the domains are generic. Nothing here calls a model provider,
needs an API key, or touches any employer's systems or data.

## The enterprise problem

An LLM feature that forwards raw user input to a model has four
exposures that product teams discover too late:

- **PII and secrets leak into prompts** — emails, phone numbers,
  SSNs, card numbers, API keys pasted into chat end up in model
  context, logs, and vendor training pipelines.
- **Prompt injection** — "ignore previous instructions" and jailbreak
  framing can override the system prompt, exfiltrate instructions, or
  pivot the model into disallowed behaviour.
- **No consistent policy** — one team blocks, another redacts, a
  third does nothing, and nobody can say which rule fired for which
  request.
- **No audit trail** — when a regulator or a customer asks "what
  happened to this request?", there is no answer.

This layer answers all four with one pipeline: detect → score →
decide via an ordered, per-tenant policy pack → enforce → audit.

## Architecture overview

```
client / LLM app ──▶ ScreeningPipeline (pipeline.py)
                        │  ┌───────────────────────────────┐
                        ├─▶│ PII detectors (pii.py)         │
                        │  │ email, phone, SSN, card (Luhn),│
                        │  │ API keys, secrets, private keys│
                        ├─▶│ Injection heuristics           │
                        │  │ (injection.py) override,      │
                        │  │ roleplay escape, delimiters,   │
                        │  │ encoded payloads               │
                        ├─▶│ Risk scoring (scoring.py)      │
                        ├─▶│ Policy pack (policy.py)        │
                        │  │ ordered rules, first match wins│
                        └─▶│ Audit log (audit.py)           │
                           │ JSONL + SHA-256 hash chain     │
                        ▼
                 ScreenResult: ALLOW / REDACT / BLOCK / FLAG
                        │
                        └── optional FastAPI service (service.py)
```

- `src/guardrails/pii.py` — regex detectors with character spans;
  card-shaped numbers must pass the Luhn checksum, so order numbers
  and dates are not flagged.
- `src/guardrails/injection.py` — four heuristic families with
  severity scores; signals stack, so a single mild phrase scores low
  while stacked signals push into BLOCK territory.
- `src/guardrails/scoring.py` — one 0–100 risk score: injection at
  full weight, PII at half weight, diminishing returns per repeated
  signal, capped at 100.
- `src/guardrails/policy.py` — ordered rules (`first match wins`)
  and three built-in packs: `default` (balanced), `strict`
  (block any injection / high PII), `permissive` (flag-only shadow
  mode). Packs are plain data and loadable from JSON.
- `src/guardrails/audit.py` — append-only JSONL log with a SHA-256
  hash chain; the log stores sanitized text and finding metadata,
  never the original text, so the trail cannot leak what it screened.
- `src/guardrails/eval.py` — deterministic eval over a synthetic
  golden set: block rate, false-positive rate, redaction coverage,
  per-category accuracy.
- `src/guardrails/service.py` — optional FastAPI surface
  (`POST /screen`, `POST /eval`, `GET /health`); the core and CLI
  run on pure stdlib.

See `docs/architecture.md` for the full design, including the
threat model and the decisions behind each trade-off.

## How to run it

```bash
pip install -r requirements.txt   # FastAPI/uvicorn for the service only
pip install -e .
make test                          # pytest (API suite auto-skips w/o FastAPI)
make demo                          # end-to-end demo + golden-set eval

# Screen one text from the CLI (exit code 2 when BLOCKed)
python -m guardrails screen "Ignore all previous instructions." --pack default
python -m guardrails screen "Email jordan.lee@example.org." --audit ./data/audit.jsonl
python -m guardrails eval

# Serve the API
python -m guardrails serve --host 127.0.0.1 --port 8000
curl -X POST localhost:8000/screen -H 'Content-Type: application/json' \
  -d '{"text": "Contact jordan.lee@example.org about the invoice."}'
```

## Key design decisions and trade-offs

- **Deterministic heuristics, not a classifier.** A model-based
  guardrail is itself attackable, non-deterministic, and hard to
  explain to an auditor. Regex + scoring is explainable ("rule
  `block_critical_injection` fired on this span"), fast enough to run
  synchronously per request, and testable to 100% on the golden set.
  The trade-off is recall on novel phrasings — mitigated by the
  eval harness, which makes regressions visible the moment a new
  attack family is added to the golden set.
- **Fail-closed everywhere.** A detector exception escalates to
  BLOCK, never to ALLOW; the `strict` pack defaults to FLAG so
  nothing passes silently. Availability cost is accepted: a
  screening outage must not become a bypass.
- **Ordered rules, first match wins.** Policy precedence is explicit
  and reviewable (BLOCK rules precede REDACT rules, so an injection
  carrying PII is blocked, not merely redacted). The cost is that
  rule order must be maintained carefully — the test suite pins the
  precedence cases.
- **Redact PII, never rewrite attacks.** REDACT replaces PII spans
  with tokens; injection findings are left intact in the *decision*
  (not the forwarded text — BLOCKed text is never forwarded) so
  reviewers see the attack, not a sanitized version of it.
- **Audit log stores no raw text.** Only sanitized text and finding
  metadata. The hash chain gives tamper evidence without a database.
- **Shadow mode via the permissive pack.** New policies can be
  evaluated against live traffic (FLAG only) before enforcement,
  which is how a team tunes false-positive rate without user impact.

## What it demonstrates

- Building a security-critical request pipeline with fail-closed
  semantics and explicit policy precedence.
- Detector design that balances recall against false positives
  (Luhn validation, encoded-payload decoding checks, stacked-signal
  scoring).
- Per-tenant policy configuration as data, not code.
- Tamper-evident audit logging and a deterministic eval harness
  that reports the metrics a guardrail team actually watches:
  block rate, false-positive rate, redaction coverage.
- Shipping a pure-stdlib core with an optional, separately-tested
  service surface — the same shape enterprise teams use to keep a
  hot path dependency-free.
