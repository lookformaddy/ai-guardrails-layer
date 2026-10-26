"""Policy packs: ordered rules mapping detections to actions.

Rules are evaluated in order; the first match wins. This is the
fail-closed heart of the layer: a pack with no matching rule falls
through to its default action, and the ``strict`` pack defaults to
FLAG so nothing passes silently unreviewed.

Packs are plain data, so a tenant's pack can be defined in code, in
JSON (see :func:`pack_from_dict`), or per-tenant in a config file
without touching the pipeline.

Three built-in packs:
- ``default`` — balanced: block critical/high injection, redact PII,
  flag medium injection, allow the rest.
- ``strict`` — block any injection signal and any high-severity PII;
  redact remaining PII; default FLAG.
- ``permissive`` — flag only; never block or redact. Useful for
  shadow-mode evaluation, where you measure what *would* have
  happened before enforcing.
"""

from __future__ import annotations

from .models import Action, PolicyPack, PolicyRule, Severity

DEFAULT_PACK = PolicyPack(
    name="default",
    rules=[
        PolicyRule(
            name="block_critical_injection",
            action=Action.BLOCK,
            kinds=("injection",),
            min_severity=Severity.CRITICAL,
            reason="Critical injection signal (instruction override / jailbreak)",
        ),
        PolicyRule(
            name="block_high_injection",
            action=Action.BLOCK,
            kinds=("injection",),
            min_severity=Severity.HIGH,
            min_risk_score=70.0,
            reason="High-severity injection with high aggregate risk",
        ),
        PolicyRule(
            name="block_critical_pii",
            action=Action.BLOCK,
            kinds=("pii",),
            min_severity=Severity.CRITICAL,
            reason="Critical secret material (e.g. private key) must not reach a model",
        ),
        PolicyRule(
            name="redact_pii",
            action=Action.REDACT,
            kinds=("pii",),
            reason="PII detected; redact before forwarding",
        ),
        PolicyRule(
            name="flag_medium_injection",
            action=Action.FLAG,
            kinds=("injection",),
            min_severity=Severity.MEDIUM,
            reason="Medium injection signal; forward with a flag for review",
        ),
    ],
    default_action=Action.ALLOW,
)

STRICT_PACK = PolicyPack(
    name="strict",
    rules=[
        PolicyRule(
            name="block_any_injection",
            action=Action.BLOCK,
            kinds=("injection",),
            reason="Strict pack: any injection signal blocks",
        ),
        PolicyRule(
            name="block_high_pii",
            action=Action.BLOCK,
            kinds=("pii",),
            min_severity=Severity.HIGH,
            reason="Strict pack: high-severity PII blocks",
        ),
        PolicyRule(
            name="redact_pii",
            action=Action.REDACT,
            kinds=("pii",),
            reason="PII detected; redact before forwarding",
        ),
    ],
    default_action=Action.FLAG,
)

PERMISSIVE_PACK = PolicyPack(
    name="permissive",
    rules=[
        PolicyRule(
            name="flag_any_signal",
            action=Action.FLAG,
            kinds=("injection", "pii"),
            reason="Permissive pack: flag only, never block or redact",
        ),
    ],
    default_action=Action.ALLOW,
)

BUILTIN_PACKS: dict[str, PolicyPack] = {
    "default": DEFAULT_PACK,
    "strict": STRICT_PACK,
    "permissive": PERMISSIVE_PACK,
}


def pack_from_dict(data: dict) -> PolicyPack:
    """Build a pack from a JSON-compatible dict.

    Expected shape::

        {
          "name": "support-team",
          "default_action": "ALLOW",
          "rules": [
            {"name": "block_jailbreak", "action": "BLOCK",
             "kinds": ["injection"], "min_severity": "HIGH",
             "reason": "..."}
          ]
        }
    """
    rules = []
    for raw in data.get("rules", []):
        rules.append(PolicyRule(
            name=raw["name"],
            action=Action(raw["action"]),
            kinds=tuple(raw.get("kinds", ())),
            min_severity=Severity(raw["min_severity"])
            if raw.get("min_severity") else None,
            min_risk_score=raw.get("min_risk_score"),
            tenant=raw.get("tenant"),
            reason=raw.get("reason", ""),
        ))
    return PolicyPack(
        name=data["name"],
        rules=rules,
        default_action=Action(data.get("default_action", "ALLOW")),
    )
