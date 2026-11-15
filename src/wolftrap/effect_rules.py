"""Stage 5.2 conditional protected-effect boundary signals.

This is an intentionally narrow lexical inspector, not a language interpreter,
data-flow engine, exploit proof, or authority decision. Source is never executed.
Findings expose fixed rule/context names and source line numbers, not literals.
"""

from __future__ import annotations

import re
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
    return "\n".join(
        "" if line.lstrip().startswith("#") else line
        for line in source.split("\n")
    )


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
        dangerous = r"['\"](?:--yolo|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox)['\"]"
        if re.search(dangerous, text) and re.search(r"\b(?:commandArgs|spawn|exec|args|argv)\b", text):
            add("WT-EFFECT-001", _line(text, dangerous), "AGENT_EXECUTION",
                "UNRESTRICTED_CLI_FLAG_IN_COMMAND_SOURCE")

        host_credential = r"(?:\.codex|\.claude|auth\.json|\.gemini)"
        copy_op = r"\b(?:cpSync|copyFileSync|copySync|copytree)\s*\("
        if re.search(host_credential, text, re.I) and re.search(copy_op, text) and re.search(
            r"(?:homedir\s*\(|HOME|host|tempHome|worker)", text, re.I
        ):
            add("WT-EFFECT-002", _line(text, copy_op), "HOST_TO_AGENT_SECRET",
                "CREDENTIAL_DIRECTORY_COPY_REVIEW")

        bypass = r"(?:GD_UNSAFE_NO_SANDBOX|UNSAFE_NO_SANDBOX|DISABLE_AGENT_SANDBOX)"
        if re.search(bypass, text) and re.search(r"(?:process\.env|env\[|getenv\s*\()", text):
            add("WT-EFFECT-003", _line(text, bypass), "SANDBOX_CONTROL",
                "EXPLICIT_SANDBOX_BYPASS_CONFIG")

        broad_mount = r"['\"]--(?:dev-)?bind['\"]\s*,\s*['\"]/['\"]\s*,\s*['\"]/['\"]"
        if re.search(broad_mount, text) and not re.search(r"--unshare-net|--unshare-all", text):
            add("WT-EFFECT-004", _line(text, broad_mount), "FILESYSTEM_AND_NETWORK_ISOLATION",
                "BROAD_ROOT_BIND_WITHOUT_LOCAL_NET_NAMESPACE_MARKER")

        if (re.search(r"\blocalStorage\.(?:setItem|getItem)\s*\(", text)
                and re.search(r"\b(?:apiKey|api_key|API_KEY|accessToken)\b", text)
                and re.search(r"\b(?:write|read|setItem|getItem)\s*\(", text)):
            add("WT-EFFECT-005", _line(text, r"\blocalStorage\."), "BROWSER_SECRET_STORAGE",
                "LOCAL_BROWSER_API_CREDENTIAL_PERSISTENCE")

        if (re.search(r"\bfetch\s*\(", text)
                and re.search(r"\b(?:apiKey|api_key|API_KEY)\b", text)
                and re.search(r"(?:['\"]x-api-key['\"]|\bAuthorization\s*:)", text)):
            add("WT-EFFECT-006", _line(text, r"(?:['\"]x-api-key['\"]|\bAuthorization\s*:)"),
                "BROWSER_OUTBOUND_AUTH", "CLIENT_MANAGED_KEY_TRANSMISSION")

        fetch = r"\b(?:https?|client)\.get\s*\("
        url_check = r"\b(?:isSafeUrl|isAllowedUrl|validateUrl|isPrivateHost)\b"
        if (re.search(fetch, text) and re.search(url_check, text)
                and re.search(r"localhost|127\.0\.0\.1|isPrivate", text, re.I)
                and not re.search(r"\b(?:dns\.lookup|dns\.promises\.lookup|lookup\s*\(|getaddrinfo\s*\()", text)):
            add("WT-EFFECT-007", _line(text, fetch), "NETWORK_FETCH_TRUST",
                "LITERAL_HOST_FILTER_DNS_REBINDING_NOT_ESTABLISHED")

        chunks = r"Buffer\.concat\s*\(\s*chunks\s*\)"
        if (re.search(chunks, text) and re.search(r"\.on\s*\(\s*['\"]data['\"]", text)
                and re.search(r"chunks\.push\s*\(", text)
                and not re.search(r"(?:MAX_(?:RESPONSE|BODY|ASSET)_BYTES|max(?:imum)?Bytes|bytesReceived\s*>|totalBytes\s*>)", text)):
            add("WT-EFFECT-008", _line(text, chunks), "REMOTE_ASSET_RESOURCE_BOUND",
                "RESPONSE_BYTE_CEILING_NOT_RECOGNIZED")

    elif suffix == ".md":
        text = source
        frontmatter = ""
        if text.startswith("---\n"):
            closing = text.find("\n---", 4)
            if 0 < closing <= 8192:
                frontmatter = text[:closing]
        if (re.search(r"allowed-tools\s*:", frontmatter, re.I)
                and re.search(r"['\"]?\w+\*:\*['\"]?", frontmatter)
                and re.search(r"\bBash\b", frontmatter)):
            add("WT-EFFECT-010", _line(text, r"\w+\*:\*"), "AGENT_TOOL_SCOPE",
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
            r"|(?:treat|consider)\s+(?:this\s+skill|these\s+instructions)\s+(?:as\s+)?(?:higher\s+priority|system|developer)"
            r"|you\s+(?:now|already)\s+have\s+(?:full|root|admin|system)\s+(?:authority|permissions|privileges)"
            r"|(?:do\s+not|never)\s+(?:verify|recheck)\s+(?:permissions|authorization|authority)"
            r")\b"
        )
        if re.search(override, text):
            add("WT-EFFECT-011", _line(text, override), "INSTRUCTION_VS_AUTHORITY",
                "SELF_ASSERTED_AUTHORITY_OR_APPROVAL_SUPPRESSION")

    elif suffix == ".py":
        text = _shell_without_comments(source)
        if (re.search(r"--api-key", text) and re.search(r"--api-url", text)
                and re.search(r"(?:X-Goog-Api-Key|Authorization)", text)
                and re.search(r"(?:urlopen|requests\.(?:post|put)|httpx\.(?:post|put)|Request\s*\()", text)
                and not re.search(r"(?:ALLOWED_(?:HOSTS|ORIGINS)|TRUSTED_HOSTS|allowed_hosts)", text)):
            add("WT-EFFECT-012", _line(text, r"--api-key"), "KEYED_EXTERNAL_EFFECT",
                "CLI_SECRET_AND_UNCONSTRAINED_ENDPOINT_REVIEW")

    elif suffix == ".sh":
        text = _shell_without_comments(source)
        if (re.search(r"\bcurl\b", text) and re.search(r"(?:^|\s)-L(?:\s|$)", text, re.M)
                and re.search(r"(?:^|\s)-o(?:\s|$)", text, re.M)
                and re.search(r"\$\{?(?:URL|url)\}?", text)
                and not re.search(r"(?:--max-filesize|--max-time|--proto-redir|ALLOWED_HOST|TRUSTED_HOST)", text)):
            add("WT-EFFECT-013", _line(text, r"\bcurl\b"), "SHELL_REMOTE_ASSET_FETCH",
                "REDIRECT_AND_RESPONSE_SIZE_POLICY_UNRESOLVED")

    return signals
