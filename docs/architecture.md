# Architecture — ai-guardrails-layer

## Problem restated

An LLM application forwards user text to a model and returns model
text to a user. Both directions cross a trust boundary, and the
application owner is accountable for what crosses it: personal data,
secrets, and adversarial instructions going in; disallowed or leaking
content coming out. This project covers the inbound direction (the
outbound direction reuses the same detectors on model output) and
gives the owner three things: a decision, a reason, and a receipt.

## Components

### Detectors (`pii.py`, `injection.py`)

Detectors are independent passes that return `Finding` objects with
character spans into the original text. Independence matters: a new
detector family can be added without touching the pipeline, and each
family can be tuned (and false-positive-tested) on its own.

- **PII detectors** are regex-based. The two subtleties that keep
  false positives down: credit-card shapes must pass the Luhn
  checksum, and overlapping findings are de-duplicated by keeping the
  longest span (so an `api_key:` label match swallows the bare
  `sk-...` token match inside it).
- **Injection heuristics** are grouped into four families —
  instruction override, roleplay escape, delimiter smuggling, encoded
  payloads — each with its own severity scale. Encoded-payload
  detection decodes base64 candidates and only flags them when the
  decoded content is instruction-like or the blob is unusually long,
  so ordinary tokens and hashes pass through.

### Risk scoring (`scoring.py`)

One number, 0–100, from all findings. Injection counts at full
weight (it signals intent), PII at half weight (it signals
exposure). Within a family, contributions diminish geometrically
(0.7× per additional finding) so a long benign text with many phone
numbers cannot out-score a genuine jailbreak. Bands: LOW < 30,
MEDIUM 30–69, HIGH ≥ 70. The score is an input to policy rules
(e.g. "block high-severity injection only when the aggregate score
is also high"), not a decision by itself.

### Policy engine (`policy.py`, `models.py`)

A `PolicyPack` is an ordered list of `PolicyRule`s plus a default
action. Rules match on finding-kind prefixes, minimum severity, and
minimum risk score, optionally scoped to a tenant. First match wins.
Built-in packs:

| Pack | Behaviour |
|------|-----------|
| `default` | Block critical/high injection, block critical secrets, redact PII, flag medium injection, else allow. |
| `strict` | Block any injection signal and any high-severity PII; default FLAG. |
| `permissive` | Flag only — shadow mode for measuring a policy before enforcing it. |

Packs are data: `pack_from_dict` builds one from JSON, so tenants
can be configured without code changes.

### Pipeline (`pipeline.py`)

Fixed order: detect → score → decide → enforce → audit.

- **BLOCK**: sanitized text is empty; nothing is forwarded.
- **REDACT**: PII spans replaced with tokens (`[REDACTED:EMAIL]`,
  etc.); injection findings are not edited out of forwarded text
  because BLOCK already handles the injection case.
- **FLAG / ALLOW**: text passes through unchanged; the decision is
  still audited.
- **Fail-closed**: any detector exception becomes a CRITICAL
  `system.detector_error` finding, which the default pack blocks.

### Audit log (`audit.py`)

Append-only JSONL. Each record carries `prev_hash` and its own
SHA-256 `hash` over the canonical record, forming a chain: editing
or deleting a middle record breaks every later link, and
`verify_chain()` detects it. Records contain the sanitized text and
finding metadata — never the original text — so the log cannot leak
the PII it screened. Single-writer append with `fsync`; a
multi-writer deployment would put a queue or database in front.

### Eval harness (`eval.py`)

A synthetic golden set (benign / PII / injection / mixed /
pack-behaviour cases) run through the real pipeline. Reported
metrics: block rate (recall on the attack class), false-positive
rate (benign cases not allowed), redaction coverage (PII cases where
no matched PII survives in sanitized output), overall and
per-category accuracy. The harness is the regression gate: adding a
detector or reordering a rule must keep these numbers green.

### Service surface (`service.py`)

Thin FastAPI wrapper: `POST /screen`, `POST /eval`,
`GET /health`. It adds no logic — every decision still flows through
`ScreeningPipeline` — so the service can be swapped (gRPC, sidecar,
in-process library) without changing behaviour.

## Threat model (what this does and does not cover)

Covered: known-shape PII/secrets, known injection phrasings and
delimiter tricks, base64/hex/unicode-escape smuggling of
instruction-like payloads, policy misconfiguration (fail-closed
defaults, shadow mode).

Not covered, by design: novel paraphrase attacks (needs a
model-based judge or human review — the FLAG path routes there),
multilingual injection, image/audio payloads, model-output
leakage (same detectors, different integration point), and
exfiltration through a compromised model itself. The FLAG action and
the audit log are the seams where those layers attach.

## Deployment notes

- Run as a sidecar or gateway filter in front of the model call;
  latency is sub-millisecond for typical prompts (pure regex).
- Keep the audit log on durable storage; ship it to the SIEM with
  the request ID for correlation with model-call logs.
- Tune a new pack in `permissive` shadow mode first, watch the
  false-positive rate on the eval harness and on sampled live
  traffic, then promote it to `default` or `strict`.

## Diagram (text)

```
               ┌─────────────┐
  user text ──▶│  detectors   │── findings (spans, severity, score)
               └──────┬──────┘
                      ▼
               ┌─────────────┐
               │ risk scoring │── 0–100 score + band
               └──────┬──────┘
                      ▼
               ┌─────────────┐
               │ policy pack  │── ALLOW / REDACT / BLOCK / FLAG
               └──────┬──────┘
                      ▼
          enforce ────┴──── audit (JSONL + hash chain)
               │
               ▼
        forwarded text (or nothing, if BLOCKed)
```
