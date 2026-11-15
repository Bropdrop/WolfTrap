"""Conservative lexical review signals for agent trust boundaries.

This module does not execute JavaScript or implement whole-program analysis.
Only the documented local syntax is recognized. Unresolved relevant structures
produce fixed, non-source-bearing issue codes. Literal values never leave this
module through its evidence interface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_TOKENS = 32768
MAX_NESTING = 96


@dataclass(frozen=True)
class _Token:
    value: str
    kind: str
    line: int


class _Unsupported(ValueError):
    """Only fixed reason codes may be supplied."""


def _lex(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    line = 1
    while i < len(text):
        c = text[i]
        if c.isspace():
            line += c == "\n"
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            i = end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise _Unsupported("UNTERMINATED_COMMENT")
            line += text[i:end + 2].count("\n")
            i = end + 2
            continue
        token_line = line
        if c in "\"'`":
            quote = c
            i += 1
            value: list[str] = []
            while i < len(text) and text[i] != quote:
                if quote == "`" and text.startswith("${", i):
                    raise _Unsupported("TEMPLATE_INTERPOLATION_UNSUPPORTED")
                if text[i] == "\n" and quote != "`":
                    raise _Unsupported("MALFORMED_STRING")
                if text[i] == "\\":
                    i += 1
                    if i >= len(text):
                        raise _Unsupported("UNTERMINATED_STRING")
                    if text[i] == "u":
                        encoded = text[i + 1:i + 5]
                        if len(encoded) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", encoded):
                            raise _Unsupported("UNSUPPORTED_STRING_ESCAPE")
                        value.append(chr(int(encoded, 16)))
                        i += 5
                        continue
                    if text[i] == "x":
                        encoded = text[i + 1:i + 3]
                        if len(encoded) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", encoded):
                            raise _Unsupported("UNSUPPORTED_STRING_ESCAPE")
                        value.append(chr(int(encoded, 16)))
                        i += 3
                        continue
                    value.append({"n": "\n", "r": "\r", "t": "\t"}.get(text[i], text[i]))
                else:
                    value.append(text[i])
                line += text[i] == "\n"
                i += 1
            if i >= len(text):
                raise _Unsupported("UNTERMINATED_STRING")
            i += 1
            tokens.append(_Token("".join(value), "string", token_line))
        elif c.isascii() and (c.isalpha() or c in "_$"):
            end = i + 1
            while end < len(text) and text[end].isascii() and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            tokens.append(_Token(text[i:end], "id", token_line))
            i = end
        elif c.isdigit():
            end = i + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "._"):
                end += 1
            tokens.append(_Token(text[i:end], "number", token_line))
            i = end
        elif c == "\\" or c == "@" or not c.isascii():
            raise _Unsupported("IDENTIFIER_OR_DECORATOR_SYNTAX_UNSUPPORTED")
        elif c == "/" and (not tokens or tokens[-1].value in {"=", "(", ":", ",", "return", "=>", "["}):
            # Do not mistake a regex body for program tokens. Regex lexical
            # contexts are deliberately outside this recognizer's grammar.
            raise _Unsupported("REGEX_LITERAL_UNSUPPORTED")
        else:
            symbol = next((x for x in ("===", "!==", "...", "=>", "?.", "==", "!=", "&&", "||", "??", "<=", ">=", "++", "--", "+=", "-=") if text.startswith(x, i)), c)
            tokens.append(_Token(symbol, "punct", token_line))
            i += len(symbol)
        if len(tokens) > MAX_TOKENS:
            raise _Unsupported("TOKEN_BOUND_EXCEEDED")
    return tokens


def _pairs(tokens: list[_Token]) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.kind != "punct":
            continue
        if token.value in {"(", "[", "{"}:
            stack.append(index)
            if len(stack) > MAX_NESTING:
                raise _Unsupported("NESTING_BOUND_EXCEEDED")
        elif token.value in {")", "]", "}"}:
            if not stack or tokens[stack[-1]].value != {")": "(", "]": "[", "}": "{"}[token.value]:
                raise _Unsupported("MALFORMED_DELIMITERS")
            start = stack.pop()
            pairs[start] = index
            pairs[index] = start
    if stack:
        raise _Unsupported("MALFORMED_DELIMITERS")
    for index, token in enumerate(tokens):
        if token.value in {"const", "let", "var"} and token.kind == "id":
            if index + 1 >= len(tokens) or tokens[index + 1].value in {"=", ";", "}"}:
                raise _Unsupported("MALFORMED_DECLARATION")
        if token.value == "=" and (index + 1 >= len(tokens) or tokens[index + 1].value in {";", "}"}):
            raise _Unsupported("MALFORMED_ASSIGNMENT")
        if token.value == "<" and index + 1 < len(tokens) and tokens[index + 1].kind == "id":
            # TS generic type/application and JSX require a real parser.
            if index == 0 or tokens[index - 1].value in {"=", "return", "(", "=>"}:
                raise _Unsupported("JSX_OR_GENERIC_SYNTAX_UNSUPPORTED")
        if token.value == "[" and index in pairs and index and tokens[index - 1].value in {"{", ","}:
            closing = pairs[index]
            if closing + 1 < len(tokens) and tokens[closing + 1].value == ":":
                raise _Unsupported("COMPUTED_OBJECT_KEY_UNSUPPORTED")
    return pairs


def _norm(value: str) -> str:
    return re.sub(r"[_$-]", "", value).lower()


_AUTH_NAMES = {
    "authenticate", "authentication", "authorize", "authorization", "checkauth",
    "verifyauth", "isauthenticated", "isauthorized", "approve", "approval",
    "onapprove", "onapproval", "requestapproval", "validatecredentials",
    "authenticateuser", "authorizeuser", "isuserauthenticated", "isuserauthorized",
    "authcallback", "approvalcallback", "checkapproval", "requireapproval",
}
_CLASSIFIERS = {
    "classify", "classifyoutput", "classifyinput", "runclassifier",
    "checkguardrail", "moderate", "moderateoutput", "moderateinput",
    "outputguardrail", "inputguardrail", "runguardrail",
}
_SENSITIVE = {"sessiontoken", "ephemeraltoken", "ephemeralkey", "clientsecret"}
_REDACTED = {"redacted", "[redacted]", "<redacted>", "***", "[removed]", ""}


def _auth_name(value: str) -> bool:
    name = _norm(value)
    for prefix in ("mock", "demo", "fake", "stub"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name in _AUTH_NAMES


def _signal(rule: str, line: int, boundary: str, context: str) -> dict[str, object]:
    return {"rule_id": rule, "line": line, "boundary": boundary, "context": context}


def _strip_parens(tokens: list[_Token]) -> list[_Token]:
    while len(tokens) >= 2 and tokens[0].value == "(" and tokens[-1].value == ")":
        pairs = _pairs(tokens)
        if pairs.get(0) != len(tokens) - 1:
            break
        tokens = tokens[1:-1]
    return tokens


def _return_value(tokens: list[_Token]) -> tuple[list[_Token] | None, str | None]:
    """Only a single immediate return is a fully supported body outcome."""
    body = tokens[:]
    while body and body[-1].value == ";":
        body.pop()
    if not body:
        return None, "EMPTY_CALLBACK_BODY"
    if body[0].value == "throw":
        return [], None
    if body[0].value != "return":
        return None, "COMPLEX_CALLBACK_BODY"
    if len(body) == 1 or body[1].line > body[0].line:
        # JavaScript automatic semicolon insertion: return newline is void.
        return [], None
    if any(x.value in {"return", "throw", ";"} and x.kind != "string" for x in body[1:]):
        return None, "MULTIPLE_CALLBACK_STATEMENTS"
    return _strip_parens(body[1:]), None


def _literal_outcome(tokens: list[_Token], *, guardrail: bool = False) -> str | None:
    values = _strip_parens(tokens)
    if values and values[0].value == "await":
        values = values[1:]
    if len(values) == 1 and values[0].kind == "id" and values[0].value in {"true", "false"}:
        return "allow" if values[0].value == "true" else "reject"
    # Promise.resolve(literal) still has no identity/decision check.
    if len(values) >= 6 and [x.value for x in values[:4]] == ["Promise", ".", "resolve", "("] and values[-1].value == ")":
        return _literal_outcome(values[4:-1], guardrail=guardrail)
    if not values or values[0].value != "{" or values[-1].value != "}":
        return None
    pairs = _pairs(values)
    fields: dict[str, str] = {}
    index = 1
    while index < len(values) - 1:
        if values[index].value == ",":
            index += 1
            continue
        key = values[index]
        if key.kind not in {"id", "string"} or index + 2 >= len(values) or values[index + 1].value != ":":
            return None
        value = values[index + 2]
        name = _norm(key.value)
        if name in fields:
            return None
        if value.kind in {"id", "string", "number"}:
            fields[name] = value.value if value.kind == "id" else "literal"
            index += 3
        elif value.value in {"{", "[", "("} and index + 2 in pairs:
            fields[name] = "nested"
            index = pairs[index + 2] + 1
        else:
            return None
        if index < len(values) - 1 and values[index].value != ",":
            return None
    keys = {"tripwiretriggered": "false", "allow": "true", "allowed": "true"} if guardrail else {
        "authenticated": "true", "authorized": "true", "approved": "true", "success": "true",
        "allow": "true", "allowed": "true",
    }
    outcomes = []
    for key, allow in keys.items():
        if key in fields:
            if fields[key] not in {"true", "false"}:
                return None
            outcomes.append("allow" if fields[key] == allow else "reject")
    return outcomes[0] if outcomes and len(set(outcomes)) == 1 else None


def _classifier_boundary(tokens: list[_Token]) -> str | None:
    calls: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind != "id" or index + 1 >= len(tokens) or tokens[index + 1].value != "(":
            continue
        name = _norm(token.value)
        if name in _CLASSIFIERS:
            calls.append(name)
        elif index >= 2 and tokens[index - 1].value in {".", "?."}:
            receiver = _norm(tokens[index - 2].value)
            if name in {"execute", "check", "classify", "run"} and any(x in receiver for x in ("guardrail", "classifier", "moderation")):
                calls.append(receiver)
    if not calls:
        return None
    if any("input" in name for name in calls):
        return "INPUT_MODERATION"
    if any("output" in name or "moderate" in name or "moderation" in name for name in calls):
        return "OUTPUT_MODERATION"
    return "GUARDRAIL_UNSPECIFIED"


def _guardrails(tokens: list[_Token], pairs: dict[int, int]) -> tuple[list[dict], list[str]]:
    signals: list[dict] = []
    issues: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind != "id" or token.value != "try":
            continue
        opening = index + 1
        if opening >= len(tokens) or tokens[opening].value != "{":
            issues.append("MALFORMED_TRY_STATEMENT")
            continue
        closing = pairs[opening]
        body = tokens[opening + 1:closing]
        boundary = _classifier_boundary(body)
        if boundary is None:
            if any(
                t.kind == "id" and (_norm(t.value) in _CLASSIFIERS or "classifier" in _norm(t.value) or "guardrail" in _norm(t.value))
                and n + 1 < len(body) and body[n + 1].value in {"[", "?."}
                for n, t in enumerate(body)
            ):
                issues.append("DYNAMIC_CLASSIFIER_CALL_UNSUPPORTED")
            continue
        # A nested closure's call need not run; do not infer a classification.
        if any(t.kind != "string" and t.value in {"function", "=>", "if", "for", "while", "switch", "try", "?", "&&", "||"} for t in body):
            issues.append("NESTED_CLASSIFIER_FLOW_UNSUPPORTED")
            continue
        cursor = closing + 1
        if cursor >= len(tokens) or tokens[cursor].value != "catch":
            if cursor >= len(tokens) or tokens[cursor].value != "finally":
                issues.append("MALFORMED_TRY_STATEMENT")
            continue
        cursor += 1
        if cursor < len(tokens) and tokens[cursor].value == "(":
            cursor = pairs[cursor] + 1
        if cursor >= len(tokens) or tokens[cursor].value != "{":
            issues.append("MALFORMED_CATCH_STATEMENT")
            continue
        catch_end = pairs[cursor]
        if catch_end + 1 < len(tokens) and tokens[catch_end + 1].value == "finally":
            issues.append("FINALLY_OVERRIDE_UNSUPPORTED")
            continue
        catch_body = tokens[cursor + 1:catch_end]
        # Permit a direct console error/debug statement before the return.
        while len(catch_body) > 4 and [x.value for x in catch_body[:2]] == ["console", "."] and catch_body[3].value == "(":
            local_pairs = _pairs(catch_body)
            stop = local_pairs[3] + 1
            if stop < len(catch_body) and catch_body[stop].value == ";":
                stop += 1
            catch_body = catch_body[stop:]
        expression, issue = _return_value(catch_body)
        if issue:
            issues.append("GUARDRAIL_CATCH_FLOW_UNSUPPORTED")
            continue
        if expression == []:
            continue
        outcome = _literal_outcome(expression or [], guardrail=True)
        if outcome == "allow":
            signals.append(_signal("WT-AGENT-001", token.line, boundary, "CLASSIFIER_ERROR_ALLOW_OUTCOME"))
        elif outcome is None:
            issues.append("GUARDRAIL_CATCH_OUTCOME_UNRESOLVED")
    # Promise catch callbacks are relevant but not part of the try grammar.
    if _classifier_boundary(tokens) and any(
        token.value == "catch" and index and tokens[index - 1].value in {".", "?."}
        for index, token in enumerate(tokens)
    ):
        issues.append("PROMISE_GUARDRAIL_CATCH_UNSUPPORTED")
    return signals, issues


def _expression_end(tokens: list[_Token], start: int, pairs: dict[int, int]) -> int:
    index = start
    while index < len(tokens):
        if tokens[index].value in {";", ",", "}", ")", "]"}:
            break
        if index > start and tokens[index].line > tokens[index - 1].line and tokens[index].value in {"const", "let", "var", "function", "export"}:
            break
        if tokens[index].value in {"(", "[", "{"}:
            index = pairs[index] + 1
        else:
            index += 1
    return index


def _callback(tokens: list[_Token], name_index: int, pairs: dict[int, int]) -> tuple[list[_Token], list[_Token], bool] | None:
    index = name_index + 1
    if index >= len(tokens):
        return None
    if tokens[index].value in {"=", ":"}:
        index += 1
        if index < len(tokens) and tokens[index].value == "async":
            index += 1
        if index < len(tokens) and tokens[index].value == "function":
            index += 1
            if index < len(tokens) and tokens[index].kind == "id":
                index += 1
    elif tokens[index].value != "(":
        return None
    if index >= len(tokens):
        return None
    params: list[_Token]
    if tokens[index].value == "(":
        stop = pairs[index]
        params = tokens[index + 1:stop]
        index = stop + 1
    elif tokens[index].kind == "id" and index + 1 < len(tokens) and tokens[index + 1].value == "=>":
        params = tokens[index:index + 1]
        index += 1
    else:
        return None
    if index < len(tokens) and tokens[index].value == ":":
        # Basic TS return annotations; object/generic types remain unsupported.
        index += 1
        while index < len(tokens) and (tokens[index].kind == "id" or tokens[index].value in {"|", "[", "]", "."}):
            index += 1
    arrow = index < len(tokens) and tokens[index].value == "=>"
    if arrow:
        index += 1
    if index >= len(tokens):
        return None
    if tokens[index].value == "{":
        return params, tokens[index + 1:pairs[index]], True
    if arrow:
        return params, tokens[index:_expression_end(tokens, index, pairs)], False
    return None


def _meaningful_conditional(body: list[_Token], params: list[_Token]) -> bool:
    names = {t.value for t in params if t.kind == "id" and t.value not in {"string", "boolean", "number", "unknown", "any"}}
    if not names:
        return False
    for index, token in enumerate(body):
        if token.value == "if" and index + 1 < len(body) and body[index + 1].value == "(":
            pairs = _pairs(body)
            condition = body[index + 2:pairs[index + 1]]
            if names.intersection(t.value for t in condition if t.kind == "id"):
                start = pairs[index + 1] + 1
                if start < len(body) and body[start].value == "{":
                    branch = body[start + 1:pairs[start]]
                else:
                    end = next((n for n in range(start, len(body)) if body[n].value == ";"), len(body))
                    branch = body[start:end]
                outcome, issue = _return_value(branch)
                if not issue and (outcome == [] or _literal_outcome(outcome or []) == "reject"):
                    return True
    candidate = body[1:] if body and body[0].value == "return" else body
    if any(t.value in {"return", ";", "throw"} for t in candidate):
        return False
    values = [t.value for t in candidate if t.kind != "string"]
    if not names.intersection(values):
        return False
    if any(values[n:n + 2] in (["||", "true"], ["true", "||"], ["&&", "false"], ["false", "&&"]) for n in range(len(values) - 1)):
        return False
    if "?" in values:
        # A conditional with two equal literal branches is not a check.
        mark = values.index("?")
        if values[mark + 1:] in (["true", ":", "true"], ["false", ":", "false"]):
            return False
    # A member access must be on a parameter, not e.g. console.log(identity).
    parameter_member = any(
        t.value in names and index + 1 < len(candidate)
        and candidate[index + 1].value in {".", "?."}
        for index, t in enumerate(candidate)
    )
    return parameter_member or any(v in {"?", "&&", "||", "===", "==", "!==", "!=", "!"} for v in values)


def _authentication(tokens: list[_Token], pairs: dict[int, int]) -> tuple[list[dict], list[str]]:
    signals: list[dict] = []
    issues: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind not in {"id", "string"} or not _auth_name(token.value):
            continue
        # String names count only as object keys, not arbitrary data literals.
        if token.kind == "string" and (index + 1 >= len(tokens) or tokens[index + 1].value != ":"):
            continue
        callback = _callback(tokens, index, pairs)
        if callback is None:
            if index + 1 < len(tokens) and tokens[index + 1].value in {"=", ":"}:
                issues.append("AUTH_CALLBACK_SYNTAX_UNSUPPORTED")
            continue
        params, body, block = callback
        expression, issue = _return_value(body) if block else (_strip_parens(body), None)
        if issue or expression is None:
            if not _meaningful_conditional(body, params):
                issues.append("AUTH_CALLBACK_FLOW_UNRESOLVED")
            continue
        outcome = _literal_outcome(expression)
        if outcome == "allow":
            # Comments are not evidence of this callback's deployment context.
            context = "DEMO_OR_MOCK_CONTEXT" if any(x in _norm(token.value) for x in ("mock", "demo", "stub", "fake")) else "CONTEXT_NOT_ESTABLISHED"
            boundary = "APPROVAL_CALLBACK" if "approv" in _norm(token.value) else "AUTHENTICATION_CALLBACK"
            signals.append(_signal("WT-AGENT-002", token.line, boundary, context))
        elif outcome is None and expression and not _meaningful_conditional(expression, params):
            issues.append("AUTH_CALLBACK_OUTCOME_UNRESOLVED")
    return signals, issues


def _path(tokens: list[_Token], start: int) -> tuple[list[str], int, bool]:
    """Read an identifier/member chain with literal bracket keys only."""
    if start >= len(tokens) or tokens[start].kind != "id":
        return [], start, False
    names = [tokens[start].value]
    cursor = start + 1
    dynamic = False
    while cursor < len(tokens):
        if tokens[cursor].value in {".", "?."} and cursor + 1 < len(tokens) and tokens[cursor + 1].kind == "id":
            names.append(tokens[cursor + 1].value)
            cursor += 2
        elif tokens[cursor].value == "[" and cursor + 2 < len(tokens) and tokens[cursor + 2].value == "]":
            if tokens[cursor + 1].kind == "string":
                names.append(tokens[cursor + 1].value)
                cursor += 3
            else:
                dynamic = True
                break
        else:
            break
    return names, cursor, dynamic


def _sensitive_expression(tokens: list[_Token], aliases: dict[str, str]) -> str:
    tokens = _strip_parens(tokens)
    if len(tokens) == 1 and tokens[0].kind == "string":
        return "safe"
    state = "safe"
    sensitive_positions: set[int] = set()
    for index, token in enumerate(tokens):
        if (
            token.kind in {"id", "string"} and index
            and tokens[index - 1].value in {"{", ","}
            and index + 2 < len(tokens) and tokens[index + 1].value == ":"
        ):
            literal = tokens[index + 2]
            if _norm(token.value) in _SENSITIVE and literal.kind == "string" and literal.value.lower() not in _REDACTED:
                sensitive_positions.add(index)
                if state != "unknown":
                    state = "sensitive"
            # An object key names data; it is not itself a variable read.
            continue
        if token.kind != "id" or (index and tokens[index - 1].value in {".", "?."}):
            continue
        names, end, dynamic = _path(tokens, index)
        normalized = [_norm(n) for n in names]
        alias_state = aliases.get(token.value)
        sensitive = (
            alias_state == "sensitive"
            or (alias_state is None and normalized[0] in _SENSITIVE)
            or any(n in _SENSITIVE for n in normalized[1:])
            or (len(names) > 1 and normalized[0] in {"session", "realtimesession", "ephemeralsession"} and normalized[1] in {"token", "credential", "key"})
            or (len(names) > 1 and alias_state == "session_object" and normalized[1] in {"token", "credential", "key", "clientsecret"})
        )
        if alias_state == "redacted_session_object":
            sensitive = False
        if "?." in [t.value for t in tokens[index:end]] and sensitive:
            state = "unknown"
        if normalized[-1] in {"length", "byteLength".lower()} and sensitive:
            sensitive = False
        if dynamic and (sensitive or normalized[0] in {"session", "response", "data"}):
            state = "unknown"
        if alias_state == "unknown":
            state = "unknown"
        if sensitive:
            sensitive_positions.add(index)
            if state != "unknown":
                state = "sensitive"
    if sensitive_positions:
        pairs = _pairs(tokens)
        # Known JSON serialization preserves the credential. Other call
        # wrappers may sanitize, transform or substitute it: do not guess.
        for index, token in enumerate(tokens):
            if token.value != "(" or index not in pairs or not index:
                continue
            preceding = tokens[index - 1]
            if preceding.kind != "id":
                continue
            inside = any(index < pos < pairs[index] for pos in sensitive_positions)
            if not inside:
                continue
            known_json = index >= 3 and [t.value for t in tokens[index - 3:index]] == ["JSON", ".", "stringify"]
            if not known_json:
                state = "unknown"
    return state


def _function_scopes(tokens: list[_Token], pairs: dict[int, int]) -> dict[int, set[str]]:
    """Find only explicit parameter lists needed for lexical shadowing."""
    scopes: dict[int, set[str]] = {}
    for index, token in enumerate(tokens):
        if token.value != "(" or index not in pairs:
            continue
        close = pairs[index]
        cursor = close + 1
        if cursor < len(tokens) and tokens[cursor].value == ":":
            cursor += 1
            while cursor < len(tokens) and (tokens[cursor].kind == "id" or tokens[cursor].value in {"|", "[", "]", "."}):
                cursor += 1
        arrow = cursor < len(tokens) and tokens[cursor].value == "=>"
        if arrow:
            cursor += 1
        preceding = tokens[index - 1].value if index else ""
        method = index and tokens[index - 1].kind == "id" and preceding not in {"if", "while", "for", "switch", "catch", "with"}
        if cursor < len(tokens) and tokens[cursor].value == "{" and (arrow or method):
            scopes[cursor] = {
                t.value for t in tokens[index + 1:close]
                if t.kind == "id" and t.value not in {"string", "number", "boolean", "any", "unknown"}
            }
    for index, token in enumerate(tokens):
        if token.value == "=>" and index and tokens[index - 1].kind == "id" and index + 1 < len(tokens) and tokens[index + 1].value == "{":
            scopes[index + 1] = {tokens[index - 1].value}
    return scopes


def _arrow_expression_scopes(tokens: list[_Token], pairs: dict[int, int]) -> list[tuple[int, int, set[str]]]:
    scopes: list[tuple[int, int, set[str]]] = []
    for index, token in enumerate(tokens):
        if token.value != "=>" or not index or index + 1 >= len(tokens) or tokens[index + 1].value == "{":
            continue
        if tokens[index - 1].value == ")":
            begin = pairs[index - 1]
            params = {t.value for t in tokens[begin + 1:index - 1] if t.kind == "id"}
        elif tokens[index - 1].kind == "id":
            params = {tokens[index - 1].value}
        else:
            continue
        scopes.append((index + 1, _expression_end(tokens, index + 1, pairs), params))
    return scopes


def _credential_logs(tokens: list[_Token], pairs: dict[int, int]) -> tuple[list[dict], list[str]]:
    signals: list[dict] = []
    issues: list[str] = []
    aliases: dict[str, str] = {}
    browser = False
    directive_index = 0
    while directive_index < len(tokens) and tokens[directive_index].kind == "string":
        browser |= tokens[directive_index].value == "use client"
        directive_index += 1
        if directive_index < len(tokens) and tokens[directive_index].value == ";":
            directive_index += 1
    scope_parameters = _function_scopes(tokens, pairs)
    expression_scopes = _arrow_expression_scopes(tokens, pairs)
    alias_stack: list[dict[str, str]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value == "{" and token.kind == "punct":
            alias_stack.append(aliases.copy())
            for parameter in scope_parameters.get(index, ()):
                aliases[parameter] = "unknown"
        elif token.value == "}" and token.kind == "punct" and alias_stack:
            aliases = alias_stack.pop()
        if token.value in {"const", "let", "var"} and index + 2 < len(tokens):
            name_index = index + 1
            if tokens[name_index].kind == "id":
                cursor = name_index + 1
                if tokens[cursor].value == ":":
                    cursor += 1
                    while cursor < len(tokens) and (tokens[cursor].kind == "id" or tokens[cursor].value in {"|", "[", "]", "."}):
                        cursor += 1
                if cursor < len(tokens) and tokens[cursor].value == "=":
                    end = _expression_end(tokens, cursor + 1, pairs)
                    expr = tokens[cursor + 1:end]
                    value = _sensitive_expression(expr, aliases)
                    if len(expr) == 1 and expr[0].kind == "id" and (_norm(expr[0].value) == "session" or aliases.get(expr[0].value) == "session_object"):
                        value = "session_object"
                    if len(expr) == 5 and expr[0].value == "{" and expr[1].value == "token" and expr[2].value == ":" and expr[3].kind == "string" and expr[3].value.lower() in _REDACTED and expr[4].value == "}":
                        value = "redacted_session_object"
                    # A recognizably named token initialized to a synthetic
                    # placeholder still models a credential. Only explicit
                    # redaction literals establish a supported safe outcome.
                    if _norm(tokens[name_index].value) in _SENSITIVE and len(expr) == 1 and expr[0].kind == "string" and expr[0].value.lower() not in _REDACTED:
                        value = "sensitive"
                    aliases[tokens[name_index].value] = value
                    if token.value == "var" and alias_stack and value in {"sensitive", "unknown", "session_object", "redacted_session_object"}:
                        # var is function-scoped, not block-scoped. The bounded
                        # alias environment must not discard a value that can
                        # escape the block and silently claim no match.
                        issues.append("CREDENTIAL_VAR_SCOPE_UNSUPPORTED")
            elif tokens[name_index].value in {"{", "["}:
                # Destructuring credential values requires binding semantics.
                end = pairs[name_index]
                if any(_norm(t.value) in _SENSITIVE or _norm(t.value) == "token" for t in tokens[name_index + 1:end]):
                    issues.append("CREDENTIAL_DESTRUCTURING_UNSUPPORTED")
        # A reassignment invalidates simple local alias reasoning.
        if token.kind == "id" and index + 1 < len(tokens) and tokens[index + 1].value in {"=", "+=", "-="} and not (index and tokens[index - 1].value in {"const", "let", "var"}):
            if token.value in aliases or _norm(token.value) in _SENSITIVE:
                end = _expression_end(tokens, index + 2, pairs)
                replacement = _sensitive_expression(tokens[index + 2:end], aliases)
                if (
                    aliases.get(token.value) in {"sensitive", "unknown", "session_object", "redacted_session_object"}
                    or _norm(token.value) in _SENSITIVE
                    or replacement in {"sensitive", "unknown"}
                ):
                    issues.append("CREDENTIAL_ALIAS_MUTATION_UNSUPPORTED")
                aliases[token.value] = "unknown"
        if token.kind != "id" or (index and tokens[index - 1].value in {".", "?."}):
            index += 1
            continue
        names, stop, dynamic = _path(tokens, index)
        normalized = [_norm(n) for n in names]
        if (
            len(names) > 1 and stop < len(tokens)
            and tokens[stop].value in {"=", "+=", "-=", "++", "--"}
            and (
                aliases.get(names[0]) in {"sensitive", "unknown", "session_object", "redacted_session_object"}
                or normalized[0] in {"session", "realtimesession", "ephemeralsession"}
                or any(name in _SENSITIVE for name in normalized[1:])
            )
        ):
            issues.append("SESSION_CREDENTIAL_MEMBER_MUTATION_UNSUPPORTED")
        if dynamic and (names == ["console"] or names == ["window", "console"]):
            issues.append("DYNAMIC_BROWSER_SINK_UNSUPPORTED")
        if stop >= len(tokens) or tokens[stop].value != "(":
            index += 1
            continue
        console_sink = (len(names) == 2 and names[0] == "console") or (len(names) == 3 and names[:2] == ["window", "console"])
        console_sink &= normalized[-1] in {"log", "debug", "info", "warn", "error", "table", "dir"}
        event_sink = len(names) == 1 and normalized[0] in {"logevent", "displayevent", "addevent"}
        if not console_sink and not event_sink:
            index += 1
            continue
        sink_aliases = aliases.copy()
        for start, end, parameters in expression_scopes:
            if start <= index < end:
                for name in parameters:
                    sink_aliases[name] = "unknown"
        state = _sensitive_expression(tokens[stop + 1:pairs[stop]], sink_aliases)
        if state == "unknown" or dynamic:
            issues.append("SESSION_CREDENTIAL_FLOW_UNRESOLVED")
        elif state == "sensitive":
            if event_sink or browser or names[0] == "window":
                signals.append(_signal("WT-AGENT-003", token.line, "BROWSER_EVENT_DISPLAY" if event_sink else "BROWSER_DEBUG_LOG", "EXPLICIT_SESSION_CREDENTIAL_FLOW"))
            else:
                issues.append("BROWSER_LOG_CONTEXT_UNRESOLVED")
        index += 1
    return signals, issues


def inspect_text(text: str) -> tuple[list[dict], list[str]]:
    """Return deterministic conditional signals and fixed incompleteness codes.

    A result without signals is only a no-match in this bounded grammar. The
    caller must never interpret it as security certification.
    """
    try:
        tokens = _lex(text)
        pairs = _pairs(tokens)
        findings: list[dict] = []
        issues: list[str] = []
        for signals, unknowns in (
            _guardrails(tokens, pairs),
            _authentication(tokens, pairs),
            _credential_logs(tokens, pairs),
        ):
            findings.extend(signals)
            issues.extend(unknowns)
        unique = {(f["rule_id"], f["line"], f["boundary"], f["context"]): f for f in findings}
        return sorted(unique.values(), key=lambda f: (f["line"], f["rule_id"], f["boundary"])), sorted(set(issues))
    except _Unsupported as exc:
        return [], [str(exc)]
