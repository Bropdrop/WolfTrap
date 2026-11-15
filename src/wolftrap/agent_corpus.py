"""Independently labelled, inert Stage 5.1 agent-boundary review fixtures.

The labels below describe the declared source grammar, not scanner output.
No application code in these fixtures is executed. File-system fault directives
are data for the bounded challenge materializer, not paths to inspect on a host.
Only invented, non-credential placeholders occur in complete saved source inputs.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

CORPUS_VERSION = "wolftrap.agent-corpus/v1"
RULE_IDS = ("WT-AGENT-001", "WT-AGENT-002", "WT-AGENT-003")
CATEGORIES = ("positive", "negative", "ambiguous", "evasion")


# Each tuple is (rationale, complete inert JavaScript/TypeScript source).
# The eight independently specified forms per family/group are intentionally
# different syntax/decision structures rather than repeated seed-only renames.
_POSITIVE = {
    "WT-AGENT-001": (
        ("Output classification error returns a disabled tripwire.",
         "async function outputGuardrail(output) { try { return await classifyOutput(output); } catch (error) { return {tripwireTriggered: false}; } }"),
        ("Input classification error returns a disabled tripwire.",
         "async function inputGuardrail(input) { try { return await classifyInput(input); } catch (error) { return {tripwireTriggered: false}; } }"),
        ("Generic classifier error returns an explicit allow flag.",
         "function check(input) { try { return classify(input); } catch (error) { return {allow: true}; } }"),
        ("Guardrail check error returns an explicit allowed flag.",
         "function check(input) { try { return checkGuardrail(input); } catch (error) { return {allowed: true}; } }"),
        ("Classifier error returns unconditional true.",
         "function check(input) { try { return runClassifier(input); } catch (error) { return true; } }"),
        ("Output moderation error returns a disabled tripwire.",
         "async function check(output) { try { return await moderateOutput(output); } catch { return {tripwireTriggered: false}; } }"),
        ("Guardrail member execution error returns a disabled tripwire.",
         "async function check(input) { try { return await guardrail.execute(input); } catch (error) { return {tripwireTriggered: false}; } }"),
        ("Classifier member invocation error returns an allow flag.",
         "function check(input) { try { return classifier.classify(input); } catch (error) { return {allow: true}; } }"),
    ),
    "WT-AGENT-002": (
        ("Authentication declaration ignores its identity and always succeeds.",
         "function authenticate(identity) { return true; }"),
        ("Authentication arrow ignores its request and always succeeds.",
         "const authenticate = (request) => true;"),
        ("Authorization callback returns a constant successful object.",
         "const authorize = (request) => ({authorized: true});"),
        ("Approval declaration ignores the decision and returns success.",
         "function approve(decision) { return {approved: true}; }"),
        ("Explicit mock authentication stub still requires conditional review.",
         "function mockAuthenticate(identity) { return true; }"),
        ("Explicit demo approval stub still requires conditional review.",
         "const demoApprove = (request) => { return true; };"),
        ("Authentication object callback returns unconditional success.",
         "const callbacks = {authenticate: (identity) => { return {authenticated: true}; }};"),
        ("Approval object method ignores its request and returns success.",
         "const callbacks = {approve(request) { return {approved: true}; }};"),
    ),
    "WT-AGENT-003": (
        ("Explicit browser console logs a session token field.",
         "window.console.log(session.token);"),
        ("Client-marked code logs a local alias of a session token.",
         "'use client'; const credential = session.token; console.log(credential);"),
        ("Explicit browser debugger logs a session client-secret value.",
         "window.console.debug(session.client_secret.value);"),
        ("Client-marked code logs a client-secret alias from an arbitrary response.",
         "'use client'; const ephemeral = response.client_secret.value; console.info(ephemeral);"),
        ("Browser event display receives an explicit session-token alias.",
         "const sessionToken = session.token; displayEvent(sessionToken);"),
        ("Browser event logging receives a session client secret.",
         "logEvent(session.client_secret.value);"),
        ("Browser event list receives an ephemeral token alias.",
         "const ephemeralToken = response.client_secret.value; addEvent(ephemeralToken);"),
        ("Client-marked warning channel receives an explicit token field.",
         "'use client'; console.warn(session.token);"),
    ),
}

_NEGATIVE = {
    "WT-AGENT-001": (
        ("Classification failure enables the tripwire.",
         "function outputGuardrail(output) { try { return classifyOutput(output); } catch (error) { return {tripwireTriggered: true}; } }"),
        ("Classification failure returns deny-like false.",
         "function check(input) { try { return classify(input); } catch (error) { return false; } }"),
        ("Guardrail failure explicitly disallows.",
         "function check(input) { try { return checkGuardrail(input); } catch (error) { return {allow: false}; } }"),
        ("Classifier failure explicitly marks allowed false.",
         "function check(input) { try { return runClassifier(input); } catch (error) { return {allowed: false}; } }"),
        ("Output moderation failure rethrows the error.",
         "function check(output) { try { return moderateOutput(output); } catch (error) { throw error; } }"),
        ("Input classification failure throws a fixed rejection.",
         "function check(input) { try { return classifyInput(input); } catch (error) { throw new Error('synthetic rejection'); } }"),
        ("A code-like comment is not a catch-path decision.",
         "// try { classifyOutput(output); } catch (error) { return {tripwireTriggered: false}; }\nconst label = 'synthetic';"),
        ("A source-code example stored as a string is not executed syntax.",
         "const example = 'try { classifyOutput(output); } catch (error) { return {tripwireTriggered: false}; }';"),
    ),
    "WT-AGENT-002": (
        ("Authentication compares an identity claim.",
         "function authenticate(identity) { return identity.id === 'synthetic-user'; }"),
        ("Authorization compares requested scope.",
         "const authorize = (request) => request.scope === 'read';"),
        ("Authentication success depends on a verified identity field.",
         "function verifyAuth(identity) { if (!identity) { return false; } return identity.verified === true; }"),
        ("Approval returns the supplied decision rather than constant success.",
         "const approval = (decision) => decision.approved === true;"),
        ("An unconditional rejection is not mock success.",
         "function authenticate(identity) { return false; }"),
        ("An explicit mock callback can reject unconditionally.",
         "const mockAuthenticate = (identity) => ({authenticated: false});"),
        ("Authentication-like text inside a comment is inert.",
         "/* function authenticate(identity) { return true; } */\nconst ready = false;"),
        ("Authentication-like source inside a string is inert.",
         "const example = 'const authenticate = (identity) => true;';"),
    ),
    "WT-AGENT-003": (
        ("Browser logging contains a fixed redaction only.",
         "window.console.log('[REDACTED]');"),
        ("Browser logging exposes a length, not the credential value.",
         "window.console.log(session.token.length);"),
        ("Client debugging explicitly supplies a fixed redaction string.",
         "'use client'; console.debug('[redacted]');"),
        ("Browser event display receives a redacted literal object.",
         "displayEvent({token: '[REDACTED]'});"),
        ("A public event label is not a session credential.",
         "window.console.info('synthetic connection opened');"),
        ("A session counter is not a credential field.",
         "'use client'; console.log(session.count);"),
        ("Credential logging text inside a comment is inert.",
         "// window.console.log(session.token);\nconst visible = false;"),
        ("Credential logging text inside a string is inert.",
         "const example = 'window.console.log(session.client_secret.value);';"),
    ),
}

_EVASION = {
    "WT-AGENT-001": (
        ("Multiline formatting preserves the fail-open classifier catch.",
         "async function review(payload) {\n try {\n return await classifyOutput(payload);\n } catch (fault) {\n return {\n tripwireTriggered: false\n };\n }\n}"),
        ("Comments between tokens do not change the fail-open property.",
         "function review(payload){try{return classifyOutput(payload);}catch(fault){return {/* synthetic */tripwireTriggered/* marker */:false};}}"),
        ("Renaming input and exception bindings preserves the error decision.",
         "function review(candidate){try{return classifyInput(candidate);}catch(classificationFailure){return {tripwireTriggered:false};}}"),
        ("Compact formatting preserves the explicit allowed fallback.",
         "function x(v){try{return classify(v)}catch(e){return {allowed:true}}}"),
        ("Optional catch binding preserves the fail-open fallback.",
         "function check(payload) { try { return moderateOutput(payload); } catch { return {tripwireTriggered: false}; } }"),
        ("Single-quoted property key preserves the fail-open decision.",
         "function check(payload) { try { return classifyOutput(payload); } catch (fault) { return {'tripwireTriggered': false}; } }"),
        ("Double-quoted property key preserves the fail-open decision.",
         'function check(payload) { try { return classifyOutput(payload); } catch (fault) { return {"tripwireTriggered": false}; } }'),
        ("TypeScript input and return annotations preserve the fail-open branch.",
         "function check(payload: string): unknown { try { return classifyOutput(payload); } catch (fault) { return {tripwireTriggered: false}; } }"),
    ),
    "WT-AGENT-002": (
        ("Compact authentication callback remains unconditional.",
         "const authenticate=(subject)=>true;"),
        ("Multiline approval callback remains unconditional.",
         "const approve = (decision) => {\n return {\n approved: true\n };\n};"),
        ("Comments inside an authentication callback do not inspect identity.",
         "function authenticate(subject) { /* identity check intentionally stubbed */ return true; }"),
        ("An async authentication declaration still returns constant success.",
         "async function authenticate(subject) { return true; }"),
        ("Single-parameter arrow syntax preserves constant approval.",
         "const approve = decision => true;"),
        ("TypeScript identity annotation is not an identity check.",
         "function authenticate(identity: Identity): boolean { return true; }"),
        ("A quoted result-object key preserves constant authentication.",
         "const authenticate = (subject) => ({'authenticated': true});"),
        ("A commented demo callback remains conditional-review mock success.",
         "// Synthetic demo callback, never used against a real service.\nconst demoAuthenticate = (subject) => true;"),
    ),
    "WT-AGENT-003": (
        ("Renamed client-secret alias still reaches the browser console.",
         "'use client'; const shortLived = response.client_secret.value; console.log(shortLived);"),
        ("Multiline member access preserves the explicit browser flow.",
         "window\n .console\n .log(\n session.token\n );"),
        ("Comments do not break token-member exposure.",
         "window.console.log(session /* synthetic */ .token);"),
        ("A second local alias retains explicit credential provenance.",
         "'use client'; const first = session.token; const second = first; console.log(second);"),
        ("An object payload explicitly carries the session credential to display.",
         "displayEvent({kind: 'synthetic', token: session.token});"),
        ("A client event payload includes a client-secret alias.",
         "const secretForSession = response.client_secret.value; addEvent({credential: secretForSession});"),
        ("TypeScript annotation does not remove credential provenance.",
         "'use client'; const credential: string = session.token; console.error(credential);"),
        ("Leading harmless string directives do not remove a client directive.",
         "'use strict'; 'use client'; console.info(session.client_secret.value);"),
    ),
}

_AMBIGUOUS = {
    "WT-AGENT-001": (
        ("A dynamic computed classifier method is outside exact call recognition.",
         "function check(v) { try { return classifier[method](v); } catch (e) { return {tripwireTriggered: false}; } }"),
        ("A relevant helper return needs interprocedural reasoning.",
         "function check(v) { try { return classifyOutput(v); } catch (e) { return fallbackDecision(e); } }"),
        ("A dynamically computed decision key cannot establish tripwire state.",
         "function check(v) { try { return classifyOutput(v); } catch (e) { return {[flagName]: false}; } }"),
        ("A template-interpolated classification input lies outside bounded syntax.",
         "function check(v) { try { return classifyOutput(`${v}`); } catch (e) { return {tripwireTriggered: false}; } }"),
        ("A missing catch terminator makes evidence incomplete.",
         "function check(v) { try { return classifyOutput(v); } catch (e) { return {tripwireTriggered: false};"),
        ("An unterminated string makes source evidence malformed.",
         "function check(v) { try { return classifyOutput('unterminated); } catch (e) { return false; } }"),
        ("A regular-expression literal is outside the bounded lexer grammar.",
         "const pattern = /guardrail/; function check(v) { try { return classifyOutput(v); } catch (e) { return {tripwireTriggered: false}; } }"),
        ("Optional classifier invocation cannot establish the supported call path.",
         "function check(v) { try { return classifyOutput?.(v); } catch (e) { return {tripwireTriggered: false}; } }"),
    ),
    "WT-AGENT-002": (
        ("Authentication delegated to a helper needs interprocedural evaluation.",
         "function authenticate(identity) { return verifyIdentity(identity); }"),
        ("Dynamic callback selection is outside direct callback recognition.",
         "const callbacks = {[callbackName]: (identity) => true};"),
        ("Optional authentication helper invocation is unresolved.",
         "function authenticate(identity) { return verifyIdentity?.(identity); }"),
        ("JSX syntax in an authentication callback is unsupported.",
         "const authenticate = (identity) => <Decision approved={true} />;"),
        ("A template expression cannot be classified as an approval decision.",
         "const approve = (decision) => `${decision}`;"),
        ("An unmatched parameter delimiter invalidates authentication source.",
         "function authenticate(identity { return true; }"),
        ("A truncated callback body invalidates approval source.",
         "const approve = (decision) => { return true;"),
        ("A dynamic result-object key leaves authentication semantics unknown.",
         "const authenticate = (identity) => ({[resultKey]: true});"),
    ),
    "WT-AGENT-003": (
        ("Plain console logging cannot prove browser visibility.",
         "console.log(session.token);"),
        ("A dynamic credential property cannot establish the supported source.",
         "window.console.log(session[credentialField]);"),
        ("A template interpolation can carry a credential but is unsupported.",
         "window.console.log(`session=${session.token}`);"),
        ("A dynamic console method cannot establish the supported sink.",
         "window.console[method](session.token);"),
        ("Optional session access cannot establish the exact credential source.",
         "window.console.log(session?.token);"),
        ("A relevant unknown helper may expose or redact a credential.",
         "window.console.log(transform(session.token));"),
        ("A truncated browser logger call leaves source evidence malformed.",
         "window.console.log(session.client_secret.value;"),
        ("JSX event rendering is outside explicit function-call sinks.",
         "const panel = <Event value={session.token} />;"),
    ),
}


def _boundary_cases() -> list[dict[str, Any]]:
    """Declarative safety faults; a materializer must never follow escape paths."""

    cases: list[dict[str, Any]] = []
    for extension in ("js", "ts"):
        path = "boundary." + extension
        for kind, rationale, directive in (
            ("missing", "An explicitly requested source file is missing.",
             {"kind": "missing", "path": path}),
            ("invalid_utf8", "Source bytes are not valid UTF-8.",
             {"kind": "invalid_utf8", "path": path, "hex": "fffe00"}),
            ("oversized", "One source file exceeds the declared 256 KiB bound.",
             {"kind": "oversized", "path": path, "character": " ", "count": 262145}),
            ("symlink", "An explicitly selected source path is a symlink.",
             {"kind": "symlink", "path": path, "target": "safe-target." + extension}),
        ):
            files = {"safe-target." + extension: "const visible = false;\n"} if kind == "symlink" else {}
            cases.append({
                "id": f"AGENT-BOUNDARY-{kind.upper()}-{extension.upper()}",
                "category": "ambiguous", "family": "BOUNDARY",
                "expected_status": "INCONCLUSIVE", "expected_rules": [],
                "files": files, "directives": [directive],
                "selected_files": [path], "synthetic_only": True,
                "rationale": rationale,
            })
    cases.extend([
        {
            "id": "AGENT-BOUNDARY-SYMLINK-DIRECTORY", "category": "ambiguous",
            "family": "BOUNDARY", "expected_status": "INCONCLUSIVE", "expected_rules": [],
            "files": {"held/entry.ts": "const visible = false;\n"},
            "directives": [{"kind": "symlink_directory", "path": "linked", "target": "held"}],
            "selected_files": ["linked/entry.ts"], "synthetic_only": True,
            "rationale": "A parent directory symlink must not be traversed.",
        },
        {
            "id": "AGENT-BOUNDARY-PARENT-ESCAPE", "category": "ambiguous",
            "family": "BOUNDARY", "expected_status": "INCONCLUSIVE", "expected_rules": [],
            "files": {"entry.ts": "const visible = false;\n"},
            "directives": [{"kind": "path_escape", "path": "../outside.ts"}],
            "selected_files": ["../outside.ts"], "synthetic_only": True,
            "rationale": "An explicit parent-directory escape is rejected without reading it.",
        },
        {
            "id": "AGENT-BOUNDARY-ABSOLUTE-ESCAPE", "category": "ambiguous",
            "family": "BOUNDARY", "expected_status": "INCONCLUSIVE", "expected_rules": [],
            "files": {"entry.ts": "const visible = false;\n"},
            "directives": [{"kind": "path_escape", "path": "/synthetic-outside.ts"}],
            "selected_files": ["/synthetic-outside.ts"], "synthetic_only": True,
            "rationale": "An explicit absolute path is rejected without reading it.",
        },
        {
            "id": "AGENT-BOUNDARY-UNSUPPORTED-EXTENSION", "category": "ambiguous",
            "family": "BOUNDARY", "expected_status": "INCONCLUSIVE", "expected_rules": [],
            "files": {"entry.txt": "function authenticate(identity) { return true; }\n"},
            "directives": [], "selected_files": ["entry.txt"], "synthetic_only": True,
            "rationale": "An explicit unsupported file extension cannot silently count as inspected.",
        },
    ])
    return cases


def corpus_cases(seed: int = 20261115) -> list[dict[str, Any]]:
    """Return 108 complete labelled fixtures in a seeded deterministic order.

    The seed controls presentation order only. Labels, syntax and case IDs are
    fixed independently, so a seed cannot change the meaning of a control.
    """

    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("agent corpus seed must be an unsigned 32-bit integer")
    definitions = {
        "positive": _POSITIVE, "negative": _NEGATIVE,
        "ambiguous": _AMBIGUOUS, "evasion": _EVASION,
    }
    cases: list[dict[str, Any]] = []
    for category in CATEGORIES:
        for rule_id in RULE_IDS:
            for index, (rationale, source) in enumerate(definitions[category][rule_id], 1):
                signal = category in {"positive", "evasion"}
                status = "REVIEW_REQUIRED" if signal else "INCONCLUSIVE" if category == "ambiguous" else "NO_PATTERN_MATCH"
                cases.append({
                    "id": f"AGENT-{rule_id[-3:]}-{category.upper()}-{index:02d}",
                    "category": category,
                    "family": rule_id,
                    "expected_status": status,
                    "expected_rules": [rule_id] if signal else [],
                    "files": {"src/fixture.ts": source + "\n"},
                    "directives": [],
                    "selected_files": ["src/fixture.ts"],
                    "synthetic_only": True,
                    "rationale": rationale,
                })
    cases.extend(_boundary_cases())
    cases.sort(key=lambda item: hashlib.sha256(f"{seed}:{item['id']}".encode("ascii")).hexdigest())
    return copy.deepcopy(cases)
