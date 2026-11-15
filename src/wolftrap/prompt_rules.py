"""Stage 5.3: deliberately narrow, offline document instruction-boundary signals.

These are *review prompts*, not vulnerability findings or decisions about the
authenticity of an alleged system prompt. Never execute or obey source text.
"""

from __future__ import annotations

from bisect import bisect_right
import json
import re
import unicodedata
from typing import Iterable


RULES = {
    "WT-PROMPT-001": "Document attempts to override higher-priority instructions",
    "WT-PROMPT-002": "Document requests disclosure of governing instructions",
    "WT-PROMPT-003": "Document claims priority over the reader's authority boundary",
    "WT-PROMPT-004": "Document requests credential extraction and outbound transfer",
}

_LEET = str.maketrans("013457", "oieast")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_QUOTED = re.compile(r"`[^`\n]*`|\"[^\"\n]*\"|'[^'\n]*'|“[^”\n]*”|‘[^’\n]*’")
_JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_REFERENCE = re.compile(
    r"^(?:example|sample|quotation|quote|attack example|anti-pattern|"
    r"malicious example|test fixture|the following illustrates)\s*:"
)
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\s+"
    r"(?:(?:all|any|the|your|previous|prior|earlier|existing|higher|current)\s+){0,5}"
    r"(?:(?:system|developer|owner|safety|policy)\s+(?:instructions?|rules|policy|"
    r"guidelines?)|(?:previous|prior|earlier)\s+instructions?|instructions?\s+from\s+"
    r"(?:the\s+)?(?:system|developer|owner))\b"
)
_SUPERSEDES = re.compile(
    r"\b(?:this|these|my|our)\s+(?:file|document|readme|message|prompt|"
    r"instructions?|directive)\s+(?:now\s+)?"
    r"(?:supersedes?|overrides?|takes?\s+priority\s+over)\s+"
    r"(?:the\s+)?(?:system|developer|owner|human|policy|operator)\b"
)
_SENSITIVE_INSTRUCTIONS = (
    r"(?:your\s+(?:own|hidden|system|developer|internal)\s+"
    r"(?:instruct(?:ions?|s)|prompts?|rules)|"
    r"(?:the\s+)?(?:system|developer|hidden|internal|secret)\s+"
    r"(?:message|instruct(?:ions?|s)|prompts?|rules))"
)
_DISCLOSE = re.compile(
    r"\b(?:reveal|dump|print|show|disclose|leak|share|send|expose)\b"
    r".{0,80}?\b" + _SENSITIVE_INSTRUCTIONS + r"\b|"
    r"\b(?:include|including)\b.{0,80}?\b"
    r"(?:your\s+own\s+(?:instruct(?:ions?|s)|prompts?)|"
    r"(?:hidden|secret)\s+system\s+prompts?)\b"
)
_NEGATED_DISCLOSURE = re.compile(
    r"\b(?:do not|don't|never|must not|should not|cannot|can't)\b"
    r"[\s*`_~-]{0,10}(?:reveal|dump|print|show|disclose|leak|include|including|share|send|expose)\b"
)
_PRIORITY = re.compile(r"\b(?:most important directive|highest priority directive|"
                       r"supersedes? all system instructions|new system-level command)\b")
_CREDENTIAL = re.compile(r"\b(?:api[ -]?key|secrets?|credentials?|tokens?|"
                         r"passwords?|private[ -]?keys?|\.env|\.ssh)\b")
_SOURCE_ACTION = re.compile(r"\b(?:read|extract|copy|collect|dump|open|obtain)\b")
_SINK_ACTION = re.compile(r"\b(?:upload|send|post|transmit|exfiltrate)\b")
_DESTINATION = re.compile(r"\b(?:https?://|webhook|endpoint|external server|"
                          r"attacker|remote url|url)\b")
_COMMAND_OVERRIDE = re.compile(
    r"^[#*\-\s]*(?:(?:you|assistant|agent)\s+"
    r"(?:must|should|need to|are to|are now instructed to)\s+)?" + _OVERRIDE.pattern
)


def _canonical(line: str) -> str:
    # NFKC + common ASCII leetspeak is bounded and intentionally non-semantic.
    # Unrecognized homoglyphs, encodings and multilingual variants are missed.
    normalized = " ".join(unicodedata.normalize("NFKC", line).casefold()
                          .translate(_LEET).split())
    # Common i/l interchange after digit normalization ("1nc1ud1ng").
    return re.sub(r"\binciud(?:ing|e)\b", "including", normalized)


def _inspect_lines(lines: Iterable[tuple[int, str]]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    fence_char = ""
    fence_length = 0
    for line_number, raw in lines:
        stripped = raw.lstrip()
        match = _FENCE.match(raw)
        if match:
            marker = match.group(1)
            if not fence_char:
                fence_char, fence_length = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_length:
                fence_char, fence_length = "", 0
            continue
        if fence_char or stripped.startswith(">"):
            continue
        line = _canonical(stripped)
        if _REFERENCE.match(line):
            continue
        # Quoted/coded examples are documentation, not top-level instructions.
        unquoted = _QUOTED.sub(" ", line)
        if not unquoted.strip():
            continue
        directive = bool(re.search(
            r"\b(?:you|your|assistant|agent|must|now|please|directive|"
            r"ignore|disregard|override|bypass|shift your focus|"
            r"print|reveal|show|share|send|disclose|dump|expose|include|including)\b", unquoted))
        signals: list[tuple[str, str]] = []
        if (_COMMAND_OVERRIDE.search(unquoted) or _SUPERSEDES.search(unquoted)) and not re.search(
            r"\b(?:do not|don't|never|must not|should not)\s+"
            r"(?:ignore|disregard|forget|override|bypass)\b", unquoted
        ):
            signals.append(("WT-PROMPT-001", "DOCUMENT_PRIORITY_OVERRIDE"))
        if directive and _DISCLOSE.search(unquoted) and not _NEGATED_DISCLOSURE.search(unquoted):
            signals.append(("WT-PROMPT-002", "READER_INSTRUCTION_DISCLOSURE"))
        if directive and _PRIORITY.search(unquoted) and (
            _DISCLOSE.search(unquoted) or _OVERRIDE.search(unquoted)
        ):
            signals.append(("WT-PROMPT-003", "UNTRUSTED_PRIORITY_CLAIM"))
        if (_CREDENTIAL.search(unquoted) and _SOURCE_ACTION.search(unquoted)
                and _SINK_ACTION.search(unquoted) and _DESTINATION.search(unquoted)):
            signals.append(("WT-PROMPT-004", "CREDENTIAL_TRANSFER_REQUEST"))
        for rule_id, context in signals:
            findings.append({"rule_id": rule_id, "line": line_number,
                             "context": context, "boundary": "UNTRUSTED_DOCUMENT_TEXT"})
    return findings


def _inspect_json_values(source: str) -> list[dict[str, object]]:
    """Scan decoded JSON string *values*; preserve original source-line locations.

    Valid JSON is mandatory. Keys and syntax are data, not agent directives.
    Strings with escaped newlines may produce multiple matches on one physical
    line; this is a deliberate bounded source-location approximation.
    """
    json.loads(source)
    newlines = [index for index, char in enumerate(source) if char == "\n"]
    findings: list[dict[str, object]] = []
    for match in _JSON_STRING.finditer(source):
        after = match.end()
        while after < len(source) and source[after].isspace():
            after += 1
        if after < len(source) and source[after] == ":":
            continue  # JSON object key, not a prompt-bearing value
        value = json.loads(match.group())
        physical_line = bisect_right(newlines, match.start()) + 1
        findings.extend(_inspect_lines((physical_line, row) for row in value.splitlines()))
    return findings


def inspect_prompt_document(relative: str, source: str) -> list[dict[str, object]]:
    """Return fixed-vocabulary line signals without copying untrusted text."""
    if relative.lower().endswith(".json"):
        return _inspect_json_values(source)
    return _inspect_lines(enumerate(source.splitlines(), start=1))
