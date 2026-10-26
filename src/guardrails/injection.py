"""Prompt-injection / jailbreak heuristics.

These are deterministic, explainable heuristics — not a classifier.
Each heuristic family contributes findings with a severity and a
0–100 score; the pipeline aggregates them into the overall risk score.
Heuristics are intentionally conservative about *what counts as an
attack*: a single mild phrase scores low, while stacked signals
(instruction override + delimiter smuggling + an encoded payload) push
the score into BLOCK territory. That stacking is what keeps benign
texts that merely *mention* instructions ("ignore the previous email")
from being blocked.

Families:
1. instruction_override — phrases that try to replace the system prompt.
2. roleplay_escape — "pretend you are / act as" jailbreak framing.
3. delimiter_smuggling — fake turn boundaries and control tokens.
4. encoded_payload — base64 / hex / unicode-escape blobs that may hide
   a payload from naive filters.
"""

from __future__ import annotations

import base64
import binascii
import re

from .models import Finding, Severity

_INSTRUCTION_OVERRIDE = [
    (r"ignore (all )?(previous|prior|above) instructions", 85.0),
    (r"disregard (the )?(system|previous|prior) (prompt|instructions)", 85.0),
    (r"override (the )?(system|previous) (prompt|instructions)", 80.0),
    (r"forget (all )?(previous|prior) instructions", 80.0),
    (r"you are (now|no longer) (bound|restricted) by", 75.0),
    (r"do not follow (your|the) (system|original) instructions", 80.0),
    (r"new (system )?instructions?:", 60.0),
    (r"system prompt (override|leak|reveal)", 70.0),
    (r"reveal (your|the) (system|hidden) prompt", 70.0),
]

_ROLEPLAY_ESCAPE = [
    (r"pretend (you are|to be) (a|an|the) ", 70.0),
    (r"act as (if )?(you are )?(a|an|the) ", 55.0),
    (r"roleplay as (a|an|the) ", 60.0),
    (r"you are (now )?DAN\b", 90.0),
    (r"\bDAN mode\b", 90.0),
    (r"jailbreak(ed)? (mode|prompt)", 90.0),
    (r"developer mode (enabled|activated)", 85.0),
    (r"unrestricted (mode|assistant)", 75.0),
    (r"hypothetically,? (if )?(you|an AI) (had|were) no (rules|restrictions)", 65.0),
]

_DELIMITER_SMUGGLING = [
    (r"<\|?(system|user|assistant|im_start|im_end)\|?>", 85.0),
    (r"\[INST\]", 80.0),
    (r"\[/INST\]", 80.0),
    (r"###\s*(system|instruction|user|assistant)\b", 65.0),
    (r"---\s*end (of )?(system|prompt|instructions)", 70.0),
    (r"(?m)^system:\s", 55.0),
    (r"(?m)^assistant:\s", 45.0),
]


def _severity_for(score: float) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    return Severity.LOW


def _scan(text: str, kind: str, patterns: list[tuple[str, float]]) -> list[Finding]:
    out: list[Finding] = []
    for pattern, score in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            out.append(Finding(
                kind=kind,
                severity=_severity_for(score),
                span=(match.start(), match.end()),
                matched_text=match.group(0),
                detail=f"Heuristic match for {kind}",
                score=score,
            ))
    return out


_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){4,}")


def _encoded_payload_findings(text: str) -> list[Finding]:
    """Flag long encoded blobs that *decode* to suspicious text.

    A long base64/hex blob alone is weak evidence (it could be a file
    hash), so it only becomes a finding when the decoded content looks
    like instructions or when the blob is unusually long. Short blobs
    and pure hex hashes are left alone.
    """
    out: list[Finding] = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True).decode(
                "utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        suspicious = any(
            word in decoded.lower()
            for word in ("ignore", "instruction", "system", "prompt",
                         "password", "secret", "disregard", "override")
        )
        if suspicious or len(blob) >= 200:
            out.append(Finding(
                kind="injection.encoded_payload",
                severity=Severity.HIGH if suspicious else Severity.MEDIUM,
                span=(match.start(), match.end()),
                matched_text=blob[:40] + ("…" if len(blob) > 40 else ""),
                detail="Base64 blob decodes to instruction-like text"
                if suspicious else "Unusually long base64 blob",
                score=80.0 if suspicious else 50.0,
            ))
    for match in _HEX_RE.finditer(text):
        blob = match.group(0)
        if len(re.sub(r"[^0-9A-Fa-f]", "", blob)) >= 64:
            # Long hex runs are usually hashes/keys; only flag when the
            # surrounding text also carries an instruction signal.
            if re.search(r"ignore|instruction|decode|execute",
                         text, flags=re.IGNORECASE):
                out.append(Finding(
                    kind="injection.encoded_payload",
                    severity=Severity.MEDIUM,
                    span=(match.start(), match.end()),
                    matched_text=blob[:40] + "…",
                    detail="Long hex blob alongside instruction language",
                    score=55.0,
                ))
    for match in _UNICODE_ESCAPE_RE.finditer(text):
        out.append(Finding(
            kind="injection.encoded_payload",
            severity=Severity.MEDIUM,
            span=(match.start(), match.end()),
            matched_text=match.group(0)[:40] + "…",
            detail="Unicode-escape sequence that may hide payload text",
            score=55.0,
        ))
    return out


def detect_injection(text: str) -> list[Finding]:
    """Return all injection/jailbreak heuristic findings, sorted by span."""
    findings: list[Finding] = []
    findings += _scan(text, "injection.instruction_override", _INSTRUCTION_OVERRIDE)
    findings += _scan(text, "injection.roleplay_escape", _ROLEPLAY_ESCAPE)
    findings += _scan(text, "injection.delimiter_smuggling", _DELIMITER_SMUGGLING)
    findings += _encoded_payload_findings(text)
    findings.sort(key=lambda f: (f.span[0], f.span[1]))
    return findings


def injection_kinds(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind.startswith("injection.")]
