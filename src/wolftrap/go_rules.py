"""Bounded, lexical Go authority-boundary triage.

Signals identify specific source patterns for human review. They do not prove
reachability, authorization bypass, effective sandboxing, or exploitability.
The scanner never executes inspected Go code and never returns source text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

RULES = {
    "WT-GO-001": "Unconditional allow result in a tool permission callback",
    "WT-GO-002": "Child process launched with inherited host environment",
    "WT-GO-003": "Proxy transport returned before a pinned direct dialer",
    "WT-GO-004": "Optional tool gate has an allow-through return",
}

MAX_SOURCE_CHARS = 256 * 1024
MAX_BRACE_DEPTH = 128
MAX_RULE_SIGNALS = 128
_IDENT = r"[A-Za-z_][A-Za-z_0-9]*"


class GoUnsupported(ValueError):
    """Only fixed, non-source-bearing reason codes may be raised."""


@dataclass(frozen=True)
class _Function:
    name: str
    body: str
    start: int


def _mask_literals_and_comments(source: str) -> str:
    """Replace all quoted/comment text with spaces, preserving offsets/lines."""
    if len(source) > MAX_SOURCE_CHARS:
        raise GoUnsupported("GO_SOURCE_BOUND_EXCEEDED")
    masked = list(source)
    n = len(source)
    i = 0

    def erase(start: int, end: int) -> None:
        for j in range(start, end):
            if source[j] != "\n":
                masked[j] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            erase(i, end)
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise GoUnsupported("GO_UNTERMINATED_BLOCK_COMMENT")
            erase(i, end + 2)
            i = end + 2
            continue
        if source[i] in {'"', "'", chr(96)}:
            quote = source[i]
            start = i
            i += 1
            while i < n:
                if source[i] == quote:
                    i += 1
                    erase(start, i)
                    break
                if quote != chr(96) and source[i] == "\n":
                    raise GoUnsupported("GO_MULTILINE_QUOTED_LITERAL")
                if quote != chr(96) and source[i] == "\\":
                    i += 1
                    if i >= n or source[i] == "\n":
                        raise GoUnsupported("GO_UNTERMINATED_QUOTED_LITERAL")
                i += 1
            else:
                raise GoUnsupported("GO_UNTERMINATED_QUOTED_LITERAL")
            continue
        i += 1
    return "".join(masked)


def _braces(masked: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for pos, char in enumerate(masked):
        if char == "{":
            stack.append(pos)
            if len(stack) > MAX_BRACE_DEPTH:
                raise GoUnsupported("GO_NESTING_BOUND_EXCEEDED")
        elif char == "}":
            if not stack:
                raise GoUnsupported("GO_UNBALANCED_BRACES")
            opening = stack.pop()
            pairs[opening] = pos
    if stack:
        raise GoUnsupported("GO_UNBALANCED_BRACES")
    return pairs


def _closing_paren(masked: str, opening: int) -> int:
    depth = 0
    for pos in range(opening, len(masked)):
        if masked[pos] == "(":
            depth += 1
            if depth > MAX_BRACE_DEPTH:
                raise GoUnsupported("GO_NESTING_BOUND_EXCEEDED")
        elif masked[pos] == ")":
            depth -= 1
            if depth == 0:
                return pos
    raise GoUnsupported("GO_UNBALANCED_PARENTHESES")


def _body(masked: str, start: int, pairs: dict[int, int]) -> tuple[int, int]:
    """Locate a function literal/declaration body after its argument list."""
    opening = masked.find("(", start)
    if opening < 0:
        raise GoUnsupported("GO_FUNCTION_BODY_UNRESOLVED")
    after_args = _closing_paren(masked, opening) + 1
    brace = masked.find("{", after_args)
    # Restrict the lookup so a malformed header does not absorb a later func.
    if brace < 0 or brace - after_args > 512 or re.search(
        r"\bfunc\b", masked[after_args:brace]
    ):
        raise GoUnsupported("GO_FUNCTION_BODY_UNRESOLVED")
    if brace not in pairs:
        raise GoUnsupported("GO_FUNCTION_BODY_UNRESOLVED")
    return brace, pairs[brace]


_FUNCTION_HEADER = re.compile(
    rf"\bfunc\s+(?:\([^{{}}]*\)\s*)?(?P<name>{_IDENT})\s*\("
)
_ALLOW_CALLBACK = re.compile(r"\bPermissions\s*:\s*func\s*\(")
_ALLOW_ONLY = re.compile(
    r"\s*return\s+permission\s*\.\s*Allowed\s*\(\s*\)\s*;?\s*"
)
_EXEC = re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\(")
_ENV = re.compile(
    rf"\b{_IDENT}\s*\.\s*Env\s*=\s*append\s*\(\s*os\s*\.\s*Environ\s*\(\s*\)"
)
_EXECUTE = re.compile(
    rf"\b{_IDENT}\s*\.\s*(?:Run|Start|Output|CombinedOutput)\s*\("
)
_PROXY_EARLY = re.compile(
    rf"\bif\s+(?P<var>{_IDENT})\s*:=\s*(?:{_IDENT}\s*\.\s*)?"
    rf"{_IDENT}ProxyTransport\s*\([^{{}};]*\)\s*;\s*(?P=var)\s*!=\s*nil\s*"
    rf"\{{\s*return\s+(?P=var)\s*\}}"
)
_PINNED_DIAL = re.compile(r"\b(?:PinnedDialer|pinnedDialer)\s*\(")
_EARLY_PASS = re.compile(
    rf"\bif\s+!\s*(?P<first>{_IDENT})\s*&&\s*!\s*(?P<second>{_IDENT})"
    r"\s*\{\s*return\s+(?:hook\s*\.\s*)?Result\s*\{\s*\}\s*\}"
)


def _functions(masked: str, pairs: dict[int, int]) -> list[_Function]:
    functions: list[_Function] = []
    for match in _FUNCTION_HEADER.finditer(masked):
        start, end = _body(masked, match.end() - 1, pairs)
        functions.append(_Function(match.group("name"), masked[start + 1:end], start + 1))
    return functions


def inspect_go_source(source: str) -> list[dict[str, str | int]]:
    """Return bounded conditional signals; raw source never leaves this API."""
    masked = _mask_literals_and_comments(source)
    pairs = _braces(masked)
    functions = _functions(masked, pairs)
    signals: list[dict[str, str | int]] = []

    def emit(rule: str, offset: int, context: str) -> None:
        if len(signals) >= MAX_RULE_SIGNALS:
            raise GoUnsupported("GO_SIGNAL_BOUND_EXCEEDED")
        signals.append({
            "rule_id": rule,
            "line": source.count("\n", 0, offset) + 1,
            "boundary": "GO_PROTECTED_EFFECT",
            "context": context,
        })

    for match in _ALLOW_CALLBACK.finditer(masked):
        brace, end = _body(masked, match.end() - 1, pairs)
        if _ALLOW_ONLY.fullmatch(masked[brace + 1:end]):
            emit("WT-GO-001", match.start(), "UNCONDITIONAL_PERMISSION_ALLOW")

    for function in functions:
        body = function.body
        launch = _EXEC.search(body)
        if launch and _ENV.search(body) and _EXECUTE.search(body):
            emit("WT-GO-002", function.start + launch.start(), "INHERITED_ENV_PROCESS_EFFECT")

        proxy = _PROXY_EARLY.search(body)
        pin = _PINNED_DIAL.search(body)
        if proxy and pin and proxy.end() < pin.start():
            emit("WT-GO-003", function.start + proxy.start(), "PROXY_PRECEDES_PINNED_DIAL")

        pass_through = _EARLY_PASS.search(body)
        if pass_through and re.search(
            r"(?i)intercept|guard|pretool|authoriz", function.name
        ) and any(
            word in (pass_through.group("first").lower(), pass_through.group("second").lower())
            for word in ("gated", "guarded", "rules", "approved")
        ):
            emit("WT-GO-004", function.start + pass_through.start(), "OPTIONAL_GATE_ALLOW_THROUGH")

    return sorted(signals, key=lambda s: (s["line"], s["rule_id"], s["context"]))
