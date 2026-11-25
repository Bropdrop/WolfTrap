"""Offline contract tests; no OpenAI calls, credentials, or money are used."""

import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from neuralscope.api_lab import plan, run, _http_transport


def config(n=1):
    return {
        "model": "mock-model-2026-01-01",
        "input_usd_per_million": "1", "output_usd_per_million": "4",
        "budget_usd": "5", "max_output_tokens": 128,
        "max_requests": n, "tariff_verified": False,
        "cases": [{"id": "case_" + str(i), "instructions": "Return JSON only.",
                   "input": "A fictional policy says DENY.",
                   "expected": {"equals_json": {"decision": "DENY"}}}
                  for i in range(n)],
    }


def response(text='{"decision":"DENY"}', **changes):
    body = {
        "id": "resp_mock", "model": "mock-model-2026-01-01", "status": "completed",
        "error": None, "incomplete_details": None, "service_tier": "default",
        "usage": {"input_tokens": 30, "output_tokens": 12, "total_tokens": 42,
                  "output_tokens_details": {"reasoning_tokens": 3}},
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": text}]}],
    }
    body.update(changes)
    return {"status_code": 200, "request_id": "req_mock", "body": body}


class ApiLabTests(unittest.TestCase):
    def test_shipped_pilot_dry_plan_preserves_source_and_sends_nothing(self):
        pilot_path = Path(__file__).resolve().parents[1] / "examples" / "api-pilot.json"
        pilot = json.loads(pilot_path.read_text())
        with mock.patch("neuralscope.api_lab.os.environ") as env, \
             mock.patch("neuralscope.api_lab._http_transport") as wire:
            env.get.side_effect = AssertionError("dry pilot must not read credentials")
            result = run(pilot)
        wire.assert_not_called()
        self.assertTrue(result["ready"])
        self.assertEqual(result["verdict"], "NOT_RUN")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["model_requested"], "gpt-6-luna")
        self.assertEqual(result["reasoning_effort"], "none")
        self.assertEqual(len(result["requests"]), 4)
        self.assertEqual(result["input_usd_per_million"], "0.125")
        self.assertEqual(result["output_usd_per_million"], "0.50")
        self.assertEqual(result["price_source"],
                         "https://developers.openai.com/api/docs/models/gpt-6-luna")
        self.assertIn("2026-11-23", pilot["description"])
        self.assertLess(float(result["reserved_cost_estimate_usd"]), 0.01)

    def test_cli_api_run_requires_explicit_live_flag(self):
        from neuralscope.__main__ import build_parser
        parser = build_parser()
        arguments = ["api-run", "--config", "example.json", "--out", "fresh-output"]
        self.assertFalse(parser.parse_args(arguments).live)
        self.assertTrue(parser.parse_args(arguments + ["--live"]).live)

    def test_dry_run_reads_no_key_and_calls_no_transport(self):
        callback = mock.Mock(side_effect=AssertionError("must not run"))
        with mock.patch("neuralscope.api_lab.os.environ") as env:
            env.get.side_effect = AssertionError("must not read credentials")
            result = run(config(), transport=callback)
        self.assertEqual(result["verdict"], "NOT_RUN")
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse(result["api_key_read"])
        callback.assert_not_called()

    def test_truthy_string_does_not_enable_network(self):
        callback = mock.Mock()
        result = run(config(), live="yes", transport=callback)
        self.assertEqual(result["verdict"], "NOT_RUN")
        callback.assert_not_called()

    def test_valid_mock_records_usage_and_exact_match(self):
        callback = mock.Mock(return_value=response())
        result = run(config(), live=True, transport=callback)
        self.assertEqual(result["verdict"], "MOCK_FIXTURE_MATCH")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["mock_transport_calls"], 1)
        self.assertEqual(result["records"][0]["usage"]["reasoning_tokens"], 3)
        self.assertEqual(result["estimated_usage_cost_usd"], "0.000078")
        self.assertIsNone(result["provider_billed_amount_usd"])
        payload = callback.call_args.args[0]
        self.assertFalse(payload["store"])
        self.assertEqual(payload["tools"], [])
        self.assertEqual(payload["tool_choice"], "none")
        self.assertEqual(payload["service_tier"], "default")
        self.assertEqual(payload["truncation"], "disabled")
        self.assertEqual(payload["max_output_tokens"], 128)
        self.assertNotIn("Authorization", json.dumps(result))

    def test_tariffs_missing_or_nonfinite_fail_before_network(self):
        for rate in (None, 0, -1, "NaN", "Infinity", True, "1e-1000000"):
            with self.subTest(rate=rate):
                data = config()
                data["input_usd_per_million"] = rate
                callback = mock.Mock()
                result = run(data, live=True, transport=callback)
                self.assertFalse(result["ready"])
                callback.assert_not_called()

    def test_cache_write_usage_is_recorded_and_checked(self):
        usage = {"input_tokens": 30, "output_tokens": 12, "total_tokens": 42,
                 "input_tokens_details": {"cached_tokens": 10, "cache_write_tokens": 20}}
        result = run(config(), live=True, transport=mock.Mock(return_value=response(usage=usage)))
        self.assertEqual(result["records"][0]["usage"]["cache_write_tokens"], 20)
        self.assertEqual(result["input_usd_per_million"], "1")
        usage["input_tokens_details"]["cache_write_tokens"] = 31
        result = run(config(), live=True, transport=mock.Mock(return_value=response(usage=usage)))
        self.assertEqual(result["halt_reason"], "INCONSISTENT_USAGE_DETAILS")

    def test_optional_reasoning_effort_controls_request_and_is_validated(self):
        data = config()
        callback = mock.Mock(return_value=response())
        run(data, live=True, transport=callback)
        self.assertNotIn("reasoning", callback.call_args.args[0])
        for effort in ("none", "low", "medium", "high", "xhigh", "max"):
            data["reasoning_effort"] = effort
            callback = mock.Mock(return_value=response())
            result = run(data, live=True, transport=callback)
            self.assertEqual(result["reasoning_effort"], effort)
            self.assertEqual(callback.call_args.args[0]["reasoning"], {"effort": effort})
        data["reasoning_effort"] = "unsupported-value"
        callback = mock.Mock()
        result = run(data, live=True, transport=callback)
        self.assertEqual(result["reason"], "REASONING_EFFORT_INVALID")
        callback.assert_not_called()

    def test_whole_experiment_budget_check_is_upfront(self):
        data = config(2)
        data["budget_usd"] = "0.000001"
        callback = mock.Mock()
        result = run(data, live=True, transport=callback)
        self.assertEqual(result["reason"], "TOTAL_COST_RESERVATION_EXCEEDS_BUDGET")
        callback.assert_not_called()

    def test_caps_and_duplicate_cases(self):
        modifications = [
            {"max_requests": 1}, {"max_total_tokens": 16}, {"max_output_tokens": 0},
            {"budget_usd": "5.01"}, {"max_input_tokens_per_request": 1024},
        ]
        for change in modifications:
            with self.subTest(change=change):
                data = config(2)
                data.update(change)
                self.assertFalse(plan(data)["ready"])
        data = config(2)
        data["cases"][1]["id"] = data["cases"][0]["id"]
        self.assertFalse(plan(data)["ready"])

    def test_real_run_requires_operator_verified_tariff_before_key_read(self):
        with mock.patch("neuralscope.api_lab.os.environ") as env:
            env.get.side_effect = AssertionError("key must not be read yet")
            result = run(config(), live=True)
        self.assertEqual(result["reason"], "CONFIRMED_TARIFF_REQUIRED")

    def test_missing_api_key_never_connects(self):
        data = config()
        data["tariff_verified"] = True
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("neuralscope.api_lab._http_transport") as callback:
            result = run(data, live=True)
        callback.assert_not_called()
        self.assertEqual(result["reason"], "API_KEY_MISSING_OR_INVALID")

    def test_missing_or_inconsistent_usage_stops_following_calls(self):
        for usage in (None, {"input_tokens": 30, "output_tokens": 12, "total_tokens": 43},
                      {"input_tokens": True, "output_tokens": 12, "total_tokens": 13}):
            with self.subTest(usage=usage):
                callback = mock.Mock(return_value=response(usage=usage))
                result = run(config(2), live=True, transport=callback)
                self.assertTrue(result["halted"])
                self.assertEqual(result["unexecuted_cases"], 1)
                self.assertEqual(callback.call_count, 1)
                self.assertEqual(result["records"][0]["outcome"], "INCONCLUSIVE")

    def test_output_limit_and_input_estimate_overrun_stop_run(self):
        for usage in ({"input_tokens": 30, "output_tokens": 129, "total_tokens": 159},
                      {"input_tokens": 10000, "output_tokens": 10, "total_tokens": 10010}):
            with self.subTest(usage=usage):
                result = run(config(2), live=True,
                             transport=mock.Mock(return_value=response(usage=usage)))
                self.assertEqual(result["halt_reason"], "TOKEN_RESERVATION_EXCEEDED")
                self.assertEqual(result["unexecuted_cases"], 1)

    def test_incomplete_correct_text_is_never_passed(self):
        result = run(config(2), live=True, transport=mock.Mock(return_value=response(
            status="incomplete", incomplete_details={"reason": "max_output_tokens"})))
        self.assertEqual(result["verdict"], "MOCK_INCONCLUSIVE")
        self.assertEqual(result["records"][0]["reason"], "RESPONSE_NOT_COMPLETE")
        self.assertEqual(result["unexecuted_cases"], 1)

    def test_refusal_is_inconclusive(self):
        item = response()
        item["body"]["output"][0]["content"] = [{"type": "refusal", "refusal": "Cannot answer."}]
        result = run(config(), live=True, transport=lambda *a, **k: item)
        self.assertEqual(result["records"][0]["reason"], "MODEL_REFUSAL")
        self.assertEqual(result["verdict"], "MOCK_INCONCLUSIVE")

    def test_parse_failures_unknown_text_and_duplicate_fields_inconclusive(self):
        for text in ('DENY', '{"decision":"ALLOW","decision":"DENY"}',
                     'NaN', '```json\n{"decision":"DENY"}\n```'):
            with self.subTest(text=text):
                result = run(config(), live=True, transport=mock.Mock(return_value=response(text)))
                self.assertEqual(result["records"][0]["outcome"], "INCONCLUSIVE")

    def test_wrong_valid_json_is_a_scoped_fixture_mismatch(self):
        result = run(config(), live=True,
                     transport=mock.Mock(return_value=response('{"decision":"ALLOW"}')))
        self.assertEqual(result["verdict"], "MOCK_FIXTURE_MISMATCH")

    def test_boolean_does_not_equal_number(self):
        data = config()
        data["cases"][0]["expected"]["equals_json"] = 1
        result = run(data, live=True, transport=mock.Mock(return_value=response('true')))
        self.assertEqual(result["verdict"], "MOCK_FIXTURE_MISMATCH")

    def test_tool_call_is_never_executed(self):
        item = response()
        item["body"]["output"] = [{"type": "function_call", "name": "run_shell",
                                   "arguments": '{"cmd":"touch /tmp/should-never-exist"}'}]
        result = run(config(), live=True, transport=lambda *a, **k: item)
        self.assertEqual(result["records"][0]["reason"], "UNEXPECTED_OUTPUT_ITEM")
        self.assertTrue(result["halted"])

    def test_timeout_keeps_reservation_and_does_not_retry(self):
        callback = mock.Mock(side_effect=TimeoutError("secret error body"))
        result = run(config(2), live=True, transport=callback)
        self.assertEqual(callback.call_count, 1)
        self.assertEqual(result["records"][0]["reason"], "AMBIGUOUS_TRANSPORT_FAILURE_NO_RETRY")
        self.assertEqual(result["reservation_consumed_usd"], result["requests"][0]["reserved_cost_estimate_usd"])
        self.assertNotIn("secret error body", json.dumps(result))

    def test_http_error_does_not_log_body_or_retry(self):
        callback = mock.Mock(return_value={"status_code": 429, "request_id": "req_a",
                                          "body": {"error": "PRIVATE_SERVER_MESSAGE"}})
        result = run(config(2), live=True, transport=callback)
        self.assertEqual(callback.call_count, 1)
        self.assertEqual(result["halt_reason"], "HTTP_STATUS_429")
        self.assertNotIn("PRIVATE_SERVER_MESSAGE", json.dumps(result))

    def test_secrets_are_scrubbed_from_mock_output(self):
        secret = "sk-synthetic-secret-only-123456789"
        result = run(config(), live=True,
                     transport=mock.Mock(return_value=response(json.dumps({"secret": secret}))))
        self.assertNotIn(secret, json.dumps(result))
        self.assertIn("[REDACTED]", result["records"][0]["output_text"])

    def test_live_secret_is_scrubbed_even_if_not_standard_key_shape(self):
        secret = "synthetic-header-secret-for-mock-test"
        data = config()
        data["tariff_verified"] = True
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": secret}, clear=True), \
             mock.patch("neuralscope.api_lab._http_transport", return_value=response(json.dumps({"secret": secret}))) as callback:
            result = run(data, live=True)
        self.assertEqual(callback.call_count, 1)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["network_calls"], 1)  # Logical attempt, HTTP itself mocked.

    def test_unexpected_exception_messages_do_not_escape(self):
        result = run(config(), live=True,
                     transport=mock.Mock(side_effect=RuntimeError("sk-secret-body-12345678")))
        self.assertEqual(result["verdict"], "MOCK_INCONCLUSIVE")
        self.assertNotIn("sk-secret", json.dumps(result))

    def test_response_model_pin_and_service_tier_fail_closed(self):
        data = config()
        data["expected_response_model"] = "different-model"
        result = run(data, live=True, transport=mock.Mock(return_value=response()))
        self.assertEqual(result["halt_reason"], "RESPONSE_MODEL_PIN_MISMATCH")
        result = run(config(), live=True, transport=mock.Mock(return_value=response(service_tier="priority")))
        self.assertEqual(result["halt_reason"], "UNEXPECTED_SERVICE_TIER")

    def test_real_transport_fixed_host_path_and_refuses_redirect(self):
        fake_response = mock.Mock()
        fake_response.status = 302
        fake_response.getheader.return_value = "req_302"
        fake_response.read.return_value = b"private redirect body"
        connection = mock.Mock()
        connection.getresponse.return_value = fake_response
        with mock.patch("neuralscope.api_lab.http.client.HTTPSConnection", return_value=connection) as constructor:
            result = _http_transport({"input": "test"}, timeout_s=3, key="synthetic")
        self.assertEqual(constructor.call_args.args[0], "api.openai.com")
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/v1/responses"))
        self.assertEqual(connection.request.call_count, 1)
        self.assertEqual(result["status_code"], 302)
        self.assertIsNone(result["body"])
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
