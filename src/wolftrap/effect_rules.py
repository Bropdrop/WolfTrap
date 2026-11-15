"""Stage 5.2 conditional protected-effect boundary signals.

This is an intentionally narrow lexical inspector, not a language interpreter,
data-flow engine, exploit proof, or authority decision. Source is never executed.
Findings expose fixed rule/context names and source line numbers, not literals.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path


RULES = {
    "WT-EFFECT-001": "Agent launched with an unrestricted execution flag",
    "WT-EFFECT-002": "Host agent credentials copied into a worker environment",
    "WT-EFFECT-003": "Explicit agent sandbox bypass switch",
    "WT-EFFECT-004": "Broad host filesystem bind with unresolved network isolation",
    "WT-EFFECT-005": "Browser API credential persisted in local storage",
    "WT-EFFECT-006": "Browser API credential used in an outbound authentication header",
    "WT-EFFECT-007": "Remote asset fetch has limited URL address validation",
    "WT-EFFECT-008": "Response chunks accumulated without a recognized byte bound",
    "WT-EFFECT-009": "Agent skill requests config credential extraction for upload",
    "WT-EFFECT-010": "Agent skill declares broad tools including shell access",
    "WT-EFFECT-011": "Agent skill instructs an authority or approval override",
    "WT-EFFECT-012": "API key and configurable endpoint passed through upload CLI",
    "WT-EFFECT-013": "Shell fetch follows remote redirects without a recognized size bound",
}

EXTENSIONS = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".sh", ".md")


def _js_without_comments(source: str) -> str:
    """Remove JS/TS comments while preserving quoted strings and line offsets.

    Regular-expression literals and embedded languages are outside this grammar;
    the scanner does not infer that absent findings make such syntax safe.
    """
    output: list[str] = []
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index:index + 2]
        if state == "line":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block":
            if following == "*/":
                output.extend("  ")
                index += 2
                state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
        elif state == "string":
            output.append(char)
            if char == "\\" and index + 1 < len(source):
                output.append(source[index + 1])
                index += 2
                continue
            if char == quote:
                state = "code"
        elif following == "//":
            output.extend("  ")
            index += 2
            state = "line"
            continue
        elif following == "/*":
            output.extend("  ")
            index += 2
            state = "block"
            continue
        else:
            output.append(char)
            if char in "\"'`":
                quote = char
                state = "string"
        index += 1
    return "".join(output)


def _shell_without_comments(source: str) -> str:
    """Mask shell comments, including inline comments, without losing lines."""
    cleaned = []
    for line in source.split("\n"):
        result = []
        quote = ""
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                result.append(char)
                escaped = False
                continue
            if char == "\\" and quote != "'":
                result.append(char)
                escaped = True
                continue
            if char in "\"'" and (not quote or char == quote):
                quote = "" if quote else char
            if char == "#" and not quote and (index == 0 or line[index - 1].isspace()):
                result.extend(" " * (len(line) - index))
                break
            result.append(char)
        cleaned.append("".join(result))
    return "\n".join(cleaned)


def _python_without_comments(source: str) -> str:
    """Mask Python COMMENT tokens while keeping code, quotes, and offsets."""
    lines = source.splitlines(keepends=True)
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                row, start = token.start
                _, end = token.end
                line = lines[row - 1]
                lines[row - 1] = line[:start] + " " * (end - start) + line[end:]
    except (tokenize.TokenError, IndentationError):
        raise ValueError("unsupported Python source tokenization") from None
    return "".join(lines)


def _python_strings(source: str) -> list[tuple[str, int]]:
    strings: list[tuple[str, int]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.STRING:
                try:
                    value = ast.literal_eval(token.string)
                except (SyntaxError, ValueError):
                    continue
                if isinstance(value, str):
                    strings.append((value, token.start[0]))
    except (tokenize.TokenError, IndentationError):
        raise ValueError("unsupported Python source tokenization") from None
    return strings


def _js_strings(source: str) -> list[tuple[str, int]]:
    """Recognize complete JS string literals, not quotes inside documentation."""
    strings: list[tuple[str, int]] = []
    index = 0
    line = 1
    while index < len(source):
        opening = source[index]
        if opening not in "\"'`":
            line += opening == "\n"
            index += 1
            continue
        start_line = line
        index += 1
        chars: list[str] = []
        while index < len(source):
            char = source[index]
            if char == "\\" and index + 1 < len(source):
                chars.append(source[index + 1])
                line += source[index + 1] == "\n"
                index += 2
                continue
            if char == opening:
                strings.append(("".join(chars), start_line))
                index += 1
                break
            chars.append(char)
            line += char == "\n"
            index += 1
    return strings


def _line(source: str, expression: str, flags: int = 0) -> int:
    match = re.search(expression, source, flags)
    return source.count("\n", 0, match.start()) + 1 if match else 1


def inspect_effect_source(relative: str, source: str) -> list[dict[str, object]]:
    """Return bounded, fixed-vocabulary conditional signals for one local file."""
    path = Path(relative)
    suffix = path.suffix.lower()
    if suffix not in EXTENSIONS or (suffix == ".md" and path.name != "SKILL.md"):
        return []

    signals: list[dict[str, object]] = []

    def add(rule: str, location: int, boundary: str, context: str) -> None:
        signals.append({"rule_id": rule, "line": location, "boundary": boundary,
                        "context": context})

    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
        text = _js_without_comments(source)
        # A flag in executable command construction is narrower than a mention
        # in a README, fixture, or arbitrary source string.
        dangerous_flags = {"--yolo", "--dangerously-skip-permissions",
                           "--dangerously-bypass-approvals-and-sandbox"}
        launch_lines = [line for value, line in _js_strings(text) if value in dangerous_flags]
        if launch_lines and re.search(r"\b(?:commandArgs|spawn|exec|args|argv)\b", text):
            add("WT-EFFECT-001", launch_lines[0], "AGENT_EXECUTION",
                "UNRESTRICTED_CLI_FLAG_IN_COMMAND_SOURCE")

        host_credential = r"(?:\.codex|\.claude|auth\.json|\.gemini)"
        copy_op = r"\b(?:cpSync|copyFileSync|copySync|copytree)\s*\(\s*([^,)\n]+)"
        for copied in re.finditer(copy_op, text):
            original = copied.group(1).strip()
            initializer = ""
            if re.fullmatch(r"[A-Za-z_$][\w$]*", original):
                declaration = re.search(
                    r"\b(?:const|let|var)\s+" + re.escape(original) + r"\s*=\s*([^;]{1,300})", text
                )
                initializer = declaration.group(1) if declaration else ""
            nearby = original + " " + initializer
            if (re.search(host_credential, nearby, re.I)
                    or (re.search(r"(?:codex|claude|gemini|auth|oauth|token|cred|secret)", original, re.I)
                        and re.search(host_credential, text, re.I))):
                if re.search(r"(?:homedir\s*\(|HOME|host|tempHome|worker)", text, re.I):
                    add("WT-EFFECT-002", text.count("\n", 0, copied.start()) + 1,
                        "HOST_TO_AGENT_SECRET", "CREDENTIAL_DIRECTORY_COPY_REVIEW")
                    break

        bypass = r"(?:GD_UNSAFE_NO_SANDBOX|UNSAFE_NO_SANDBOX|DISABLE_AGENT_SANDBOX)"
        if re.search(bypass, text) and re.search(r"(?:process\.env|env\[|getenv\s*\()", text):
            add("WT-EFFECT-003", _line(text, bypass), "SANDBOX_CONTROL",
                "EXPLICIT_SANDBOX_BYPASS_CONFIG")

        broad_mount = r"['\"]--(?:dev-)?bind['\"]\s*,\s*['\"]/['\"]\s*,\s*['\"]/['\"]"
        if re.search(broad_mount, text) and not re.search(r"--unshare-net|--unshare-all", text):
            add("WT-EFFECT-004", _line(text, broad_mount), "FILESYSTEM_AND_NETWORK_ISOLATION",
                "BROAD_ROOT_BIND_WITHOUT_LOCAL_NET_NAMESPACE_MARKER")

        storage = r"\blocalStorage\.(?:setItem|getItem)\s*\("
        credential_store = (r"(?:" + storage + r"\s*(?:['\"][^'\"]*(?:api.?key|token|credential)"
                            r"[^'\"]*['\"]|KEYS\.(?:apiKey|accessToken)|apiKey\b)"
                            r"|\b(?:write|read)\s*\(\s*KEYS\.(?:apiKey|accessToken)\b)")
        if re.search(storage, text) and re.search(credential_store, text, re.I):
            add("WT-EFFECT-005", _line(text, r"\blocalStorage\."), "BROWSER_SECRET_STORAGE",
                "LOCAL_BROWSER_API_CREDENTIAL_PERSISTENCE")

        auth_header = (
            r"(?:['\"](?:x-api-key|Authorization)['\"]|\bAuthorization)\s*:\s*([^,\n;}]*)"
            r"|\.set\s*\(\s*['\"](?:Authorization|x-api-key)['\"]\s*,\s*([^)\n]*)"
        )
        if re.search(r"\bfetch\s*\(", text):
            for header in re.finditer(auth_header, text):
                value = header.group(1) or header.group(2) or ""
                if re.search(r"\b(?:apiKey|api_key|API_KEY)\b", value):
                    add("WT-EFFECT-006", text.count("\n", 0, header.start()) + 1,
                        "BROWSER_OUTBOUND_AUTH", "CLIENT_MANAGED_KEY_TRANSMISSION")
                    break

        fetch = r"\b(?:https?|client)\.get\s*\("
        url_check = r"\b(?:isSafeUrl|isAllowedUrl|validateUrl|isPrivateHost)\b"
        relevant_dns = r"\bdns\.(?:promises\.)?lookup\s*\(\s*(?:url\.(?:host|hostname)|host|hostname|parsed\.(?:host|hostname))"
        if (re.search(fetch, text) and re.search(url_check, text)
                and re.search(r"localhost|127\.0\.0\.1|isPrivate", text, re.I)
                and not re.search(relevant_dns, text)):
            add("WT-EFFECT-007", _line(text, fetch), "NETWORK_FETCH_TRUST",
                "LITERAL_HOST_FILTER_DNS_REBINDING_NOT_ESTABLISHED")

        chunks = re.search(r"Buffer\.concat\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", text)
        if chunks:
            source_array = chunks.group(1)
            if (re.search(r"\.on\s*\(\s*['\"]data['\"]", text)
                    and re.search(r"\b" + re.escape(source_array) + r"\.push\s*\(", text)
                    and not re.search(r"(?:MAX_(?:RESPONSE|BODY|ASSET)_BYTES|max(?:imum)?Bytes|bytesReceived\s*>|totalBytes\s*>)", text)):
                add("WT-EFFECT-008", text.count("\n", 0, chunks.start()) + 1,
                    "REMOTE_ASSET_RESOURCE_BOUND", "RESPONSE_BYTE_CEILING_NOT_RECOGNIZED")

    elif suffix == ".md":
        text = source
        frontmatter = ""
        if text.startswith("---\n"):
            closing = text.find("\n---", 4)
            if 0 < closing <= 8192:
                frontmatter = text[:closing]
        wildcard = r"(?:['\"](?:\*|\*:\*|[\w-]+\*:\*)['\"]|(?m:^\s*-\s*(?:\*|\*:\*|[\w-]+\*:\*)(?:\s|$)))"
        if (re.search(r"allowed-tools\s*:", frontmatter, re.I)
                and re.search(wildcard, frontmatter)
                and re.search(r"\bBash\b", frontmatter)):
            add("WT-EFFECT-010", _line(text, wildcard), "AGENT_TOOL_SCOPE",
                "DECLARED_WILDCARD_AND_SHELL_TOOLS")

        if (re.search(r"(?:\.gemini/|~/\.claude\.json|mcp_config\.json)", text, re.I)
                and re.search(r"(?:extract|locate|read)\b.{0,80}(?:API key|credential|MCP|config)", text, re.I)
                and re.search(r"--api-key", text)
                and re.search(r"\b(?:upload|send|http)\b", text, re.I)):
            confirmation = bool(re.search(r"(?:user confirmation required|explicit approval|user confirms)", text, re.I))
            add("WT-EFFECT-009", _line(text, r"(?:\.gemini/|~/\.claude\.json|mcp_config\.json)"),
                "AGENT_INSTRUCTION_TO_EFFECT", "EXPLICIT_USER_CONFIRMATION_PRESENT" if confirmation
                else "USER_CONFIRMATION_NOT_RECOGNIZED")

        override = (
            r"(?im)^\s*(?:[-*]\s*)?(?:"
            r"(?:you\s+(?:must|should)\s+)?ignore\s+(?:all\s+)?(?:previous(?:\s+(?:system|developer|user))?|system|developer|user)\s+instructions"
            r"|(?:you\s+must\s+)?(?:skip|bypass|disable)\s+(?:human\s+)?(?:approval|authorization|confirmation)"
            r"|(?:you\s+must\s+)?(?:grant\s+yourself|self-authorize|override\s+(?:the\s+)?(?:system|developer|owner))"
            r"|(?:do\s+not|don't)\s+(?:ask|wait)\s+for\s+(?:user\s+)?(?:permission|approval|confirmation)"
            r"|(?:never|do\s+not|don't)\s+(?:request|seek|ask\s+for)\s+(?:human\s+|user\s+)?(?:approval|authorization|confirmation|permission)"
            r"|(?:treat|consider)\s+(?:this\s+skill|these\s+instructions)\s+(?:as\s+)?(?:higher\s+priority|system|developer)"
            r"|you\s+(?:(?:now|already)\s+)?have\s+(?:full\s+)?(?:root|admin|system)\s+(?:authority|permissions|privileges)"
            r"|(?:do\s+not|never)\s+(?:verify|recheck)\s+(?:permissions|authorization|authority)"
            r")\b"
        )
        if re.search(override, text):
            add("WT-EFFECT-011", _line(text, override), "INSTRUCTION_VS_AUTHORITY",
                "SELF_ASSERTED_AUTHORITY_OR_APPROVAL_SUPPRESSION")

    elif suffix == ".py":
        text = _python_without_comments(source)
        dangerous_flags = {"--yolo", "--dangerously-skip-permissions",
                           "--dangerously-bypass-approvals-and-sandbox"}
        dangerous_lines = [line for value, line in _python_strings(text) if value in dangerous_flags]
        if (dangerous_lines
                and re.search(r"\b(?:subprocess\.(?:Popen|run|call|check_call)|Popen|os\.system)\s*\(", text)):
            add("WT-EFFECT-001", dangerous_lines[0], "AGENT_EXECUTION",
                "UNRESTRICTED_CLI_FLAG_IN_COMMAND_SOURCE")

        copy_python = r"\b(?:shutil\.)?(?:copytree|copyfile|copy2|copy)\s*\("
        if (re.search(copy_python, text) and re.search(r"\.codex|\.claude|auth\.json|\.gemini", text, re.I)
                and re.search(r"(?:Path\.home\s*\(|expanduser\s*\(|os\.environ|HOME|temp_home|worker)", text, re.I)):
            add("WT-EFFECT-002", _line(text, copy_python), "HOST_TO_AGENT_SECRET",
                "CREDENTIAL_DIRECTORY_COPY_REVIEW")

        bypass = r"(?:GD_UNSAFE_NO_SANDBOX|UNSAFE_NO_SANDBOX|DISABLE_AGENT_SANDBOX)"
        if (re.search(bypass, text) and re.search(r"(?:os\.getenv|os\.environ|environ\.get)\s*[\[(]", text)):
            add("WT-EFFECT-003", _line(text, bypass), "SANDBOX_CONTROL",
                "EXPLICIT_SANDBOX_BYPASS_CONFIG")

        broad_mount = r"['\"]--(?:dev-)?bind['\"]\s*,\s*['\"]/['\"]\s*,\s*['\"]/['\"]"
        if re.search(broad_mount, text) and not re.search(r"--unshare-net|--unshare-all", text):
            add("WT-EFFECT-004", _line(text, broad_mount), "FILESYSTEM_AND_NETWORK_ISOLATION",
                "BROAD_ROOT_BIND_WITHOUT_LOCAL_NET_NAMESPACE_MARKER")

        if (re.search(r"--api-key", text) and re.search(r"--api-url", text)
                and re.search(r"(?:X-Goog-Api-Key|Authorization)", text)
                and re.search(r"(?:urlopen|requests\.(?:post|put|request)|httpx\.(?:post|put|request)|Request\s*\()", text)
                and not re.search(r"(?:ALLOWED_(?:HOSTS|ORIGINS)|TRUSTED_HOSTS|allowed_hosts)", text)):
            add("WT-EFFECT-012", _line(text, r"--api-key"), "KEYED_EXTERNAL_EFFECT",
                "CLI_SECRET_AND_UNCONSTRAINED_ENDPOINT_REVIEW")

    elif suffix == ".sh":
        text = _shell_without_comments(source)
        launch = r"(?m)^\s*(?:codex|claude|gemini|antigravity|agent)\s+[^\n]*(?:--yolo|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox)\b"
        if re.search(launch, text):
            add("WT-EFFECT-001", _line(text, launch), "AGENT_EXECUTION",
                "UNRESTRICTED_CLI_FLAG_IN_COMMAND_SOURCE")

        shell_copy = r"(?m)^\s*(?:cp|rsync)\s+[^\n]*(?:\.codex|\.claude|auth\.json|\.gemini)"
        if re.search(shell_copy, text, re.I) and re.search(r"\$(?:HOME|USERPROFILE)|~/", text):
            add("WT-EFFECT-002", _line(text, shell_copy, re.I), "HOST_TO_AGENT_SECRET",
                "CREDENTIAL_DIRECTORY_COPY_REVIEW")

        bypass = r"(?:GD_UNSAFE_NO_SANDBOX|UNSAFE_NO_SANDBOX|DISABLE_AGENT_SANDBOX)"
        if re.search(bypass, text) and re.search(r"(?:\bif\b|\btest\b|\[)", text):
            add("WT-EFFECT-003", _line(text, bypass), "SANDBOX_CONTROL",
                "EXPLICIT_SANDBOX_BYPASS_CONFIG")

        shell_mount = r"\bbwrap\b[^\n]{0,250}--(?:dev-)?bind\s+/\s+/"
        if re.search(shell_mount, text) and not re.search(r"--unshare-net|--unshare-all", text):
            add("WT-EFFECT-004", _line(text, shell_mount), "FILESYSTEM_AND_NETWORK_ISOLATION",
                "BROAD_ROOT_BIND_WITHOUT_LOCAL_NET_NAMESPACE_MARKER")

        for line_no, line in enumerate(text.splitlines(), 1):
            command = re.search(r"(?:^|\s)curl\s+([^\n]*)", line)
            if command is None:
                continue
            arguments = command.group(1)
            if (re.search(r"(?:^|\s)(?:-L|--location)(?=\s|$)", arguments)
                    and re.search(r"(?:^|\s)(?:-o|--output)(?=\s|$)", arguments)
                    and re.search(r"\$(?:\{(?:URL|url)\}|(?:URL|url)\b)", arguments)
                    and not re.search(r"--max-filesize\b|ALLOWED_HOST|TRUSTED_HOST", line)):
                add("WT-EFFECT-013", line_no, "SHELL_REMOTE_ASSET_FETCH",
                    "REDIRECT_AND_RESPONSE_SIZE_POLICY_UNRESOLVED")
                break

    return signals
