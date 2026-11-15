"""Independent semantic controls for the three bounded review families."""

from __future__ import annotations

import json
import unittest

from wolftrap.agent_rules import inspect_text


class AgentRuleTests(unittest.TestCase):
    def check(self, source: str, expected: set[str], *, unknown: bool = False):
        signals, issues = inspect_text(source)
        self.assertEqual(expected, {item["rule_id"] for item in signals}, (signals, issues))
        self.assertEqual(unknown, bool(issues), (signals, issues))
        return signals

    def test_guardrail_failure_allows(self):
        source = "async function outputGuardrail(output){try{return await classifyOutput(output);}catch(e){return {tripwireTriggered:false};}}"
        signals = self.check(source, {"WT-AGENT-001"})
        self.assertEqual("OUTPUT_MODERATION", signals[0]["boundary"])

    def test_guardrail_failure_rejects(self):
        for body in ("return {tripwireTriggered:true};", "throw new Error('reject');", "return false;"):
            self.check("try { classifyOutput(output); } catch(e) {" + body + "}", set())

    def test_guardrail_alternate_format_and_literal_key(self):
        self.check("try\n{ await classifyInput(x); }\ncatch\n{ return { 'tripwireTriggered' : false }; }", {"WT-AGENT-001"})

    def test_generic_guardrail_is_not_tool_authorization(self):
        signals = self.check("try { guardrail.execute(x); } catch(e) { return {allowed:true}; }", {"WT-AGENT-001"})
        self.assertEqual("GUARDRAIL_UNSPECIFIED", signals[0]["boundary"])

    def test_guardrail_nested_or_finally_uncertain(self):
        self.check("try { function later(){ classify(x); } } catch(e){return {tripwireTriggered:false};}", set(), unknown=True)
        self.check("try {classify(x);}catch(e){return {tripwireTriggered:false};}finally{return false;}", set(), unknown=True)
        self.check("try {if(false){classifyOutput(x);}}catch(e){return {tripwireTriggered:false};}", set(), unknown=True)

    def test_guardrail_comments_and_strings_are_not_code(self):
        self.check("// try {classify(x);} catch {return {tripwireTriggered:false};}\nconst text='try {classify(x);} catch {return true;}';", set())

    def test_unconditional_auth_forms(self):
        for source in (
            "function authenticate(identity){return true;}",
            "const authenticate = identity => true;",
            "const authenticate = async (request: Request): boolean => true;",
            "const settings={authenticate: (identity)=>({authenticated:true})};",
            "const settings={approve(decision){return {approved:true};}};",
            "const checkAuth = (request) => Promise.resolve(true);",
        ):
            self.check(source, {"WT-AGENT-002"})

    def test_demo_context_preserved_as_conditional(self):
        for source in (
            "function mockAuthenticate(identity){return true;}",
            "const demoApprove=()=>true;",
            "const fakeCheckAuth=()=>true;",
            "const stubAuthorize=()=>true;",
            "const settings={'mock_authenticate':()=>true};",
        ):
            with self.subTest(source=source):
                signals = self.check(source, {"WT-AGENT-002"})
                self.assertEqual("DEMO_OR_MOCK_CONTEXT", signals[0]["context"])

    def test_unrelated_comments_cannot_change_auth_context(self):
        for callback in ("const authenticate=()=>true;", "const approve=()=>true;"):
            baseline = self.check(callback, {"WT-AGENT-002"})[0]
            self.assertEqual("CONTEXT_NOT_ESTABLISHED", baseline["context"])
            for word in ("mock", "DEMO", "stub", "example"):
                for comment in (f"// {word} theme preview\n", f"/* {word} theme preview */"):
                    for source in (
                        comment + callback,
                        callback + comment,
                        "function preview(){" + comment + "return 1;}\n" + callback,
                        callback.replace("=>", "=>" + comment),
                    ):
                        with self.subTest(source=source):
                            signals = self.check(source, {"WT-AGENT-002"})
                            self.assertEqual(1, len(signals))
                            self.assertEqual(
                                {k: v for k, v in baseline.items() if k != "line"},
                                {k: v for k, v in signals[0].items() if k != "line"},
                            )

    def test_mock_context_is_local_to_callback_name(self):
        source = (
            "// demo theme preview\n"
            "const mockAuthenticate=()=>true;\n"
            "const authenticate=()=>true;\n"
            "const demoApprove=()=>true;\n"
            "const approve=()=>true;\n"
        )
        signals = self.check(source, {"WT-AGENT-002"})
        self.assertEqual(
            ["DEMO_OR_MOCK_CONTEXT", "CONTEXT_NOT_ESTABLISHED",
             "DEMO_OR_MOCK_CONTEXT", "CONTEXT_NOT_ESTABLISHED"],
            [signal["context"] for signal in signals],
        )

    def test_meaningful_auth_conditions_and_rejection(self):
        for source in (
            "const authenticate = identity => identity && identity.valid;",
            "function authenticate(request){if (!request.identity) return false; return true;}",
            "const approve = decision => decision === 'allow';",
            "const authenticate = () => false;",
            "const authenticate = () => ({authenticated:false});",
        ):
            self.check(source, set())

    def test_auth_unknown_helper_and_false_identity_mentions(self):
        self.check("const authenticate=identity=>check(identity);", set(), unknown=True)
        self.check("function authenticate(identity){ console.log(identity); return true; }", set(), unknown=True)
        self.check("function authenticate(identity){ if(identity) {} return true; }", set(), unknown=True)
        self.check("const authenticate = identity => identity === 'admin' || true;", set(), unknown=True)

    def test_unrelated_success_and_comment_strings_are_not_auth(self):
        for source in (
            "const healthy=()=>true;",
            "const text='const authenticate = () => true';",
            "/* const approve=()=>true; */ const count=1;",
        ):
            self.check(source, set())

    def test_session_credential_explicit_browser_sinks(self):
        for source in (
            "'use client'; const secret=session.client_secret.value; console.log(secret);",
            "window.console.debug(session.token);",
            "displayEvent({token: session.client_secret.value});",
            "'use client'; const a=session.token; const b=a; console.info(b);",
            "'use client'; const sessionToken='SYNTHETIC_NOT_A_CREDENTIAL'; console.log(sessionToken);",
            "'use client'; console.log(JSON.stringify({token:session.client_secret.value}));",
        ):
            self.check(source, {"WT-AGENT-003"})

    def test_sensitive_values_never_escape_interface(self):
        marker = "SYNTHETIC_VALUE_ONLY_NO_REAL_SECRET"
        signals = self.check("'use client'; const sessionToken='" + marker + "'; console.log(sessionToken);", {"WT-AGENT-003"})
        self.assertNotIn(marker, json.dumps(signals))
        self.assertNotIn("sessionToken", json.dumps(signals))

    def test_redacted_and_non_sensitive_logging(self):
        for source in (
            "'use client'; console.log('[REDACTED]');",
            "'use client'; const sessionToken='[REDACTED]'; console.log(sessionToken);",
            "'use client'; console.log(session.token.length);",
            "'use client'; console.log({count:1});",
            "const text='console.log(session.token)';",
        ):
            self.check(source, set())

    def test_browser_and_transform_ambiguity(self):
        self.check("console.log(session.token);", set(), unknown=True)
        self.check("'use client'; console.log(redact(session.token));", set(), unknown=True)
        self.check("'use client'; console.log(session[key]);", set(), unknown=True)
        self.check("'use client'; console.log(session?.token);", set(), unknown=True)

    def test_credential_alias_scope_and_shadowing(self):
        self.check("'use client'; const token=session.token; function render(){ const token='[redacted]'; } console.log(token);", {"WT-AGENT-003"})
        self.check("'use client'; const secret=session.token; function render(secret){ console.log(secret); }", set(), unknown=True)
        self.check("'use client'; const session={token:'[redacted]'}; console.log(session.token);", set())
        self.check("'use client'; const secret=session.token; const render=secret=>console.log(secret);", set(), unknown=True)
        self.check("'use client'; console.log({sessionToken:'[REDACTED]'});", set())
        self.check("'use client'; const metadata={ephemeralKey:'[REDACTED]'}; console.log(metadata);", set())

    def test_credential_mutations_cannot_escape_unknown_scope(self):
        for source in (
            "'use client'; let alias='[REDACTED]'; if(true){alias=session.token;} console.log(alias);",
            "'use client'; if(true){var alias=session.token;} console.log(alias);",
            "const session={token:'[redacted]'};session.token=secretSessionValue;window.console.log(session.token);",
        ):
            self.check(source, set(), unknown=True)

    def test_malformed_and_unsupported_fail_closed(self):
        for source in (
            "const x = ;", "const = 1;", "function f( {", "/* unterminated",
            "const s='broken", "const s=`token ${session.token}`;",
            "const view=<div/>;", "const re=/console.log(session.token)/;",
        ):
            self.check(source, set(), unknown=True)

    def test_determinism_and_fixed_schema(self):
        source = "'use client'; const authenticate=()=>true; console.log(session.token);"
        self.assertEqual(inspect_text(source), inspect_text(source))
        for signal in inspect_text(source)[0]:
            self.assertEqual({"rule_id", "line", "boundary", "context"}, set(signal))


if __name__ == "__main__":
    unittest.main()
