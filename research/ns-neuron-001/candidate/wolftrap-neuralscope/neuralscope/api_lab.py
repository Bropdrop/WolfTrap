"""Bounded, opt-in behavioral experiments through the OpenAI Responses API.

This module observes outputs. It does not inspect hosted model weights, execute
model-selected tools, or claim that a passing fixture establishes security.
The default path is offline and does not even read the API-key environment.

Budget figures are *local estimates*: UTF-8 bytes plus a 1,024-token envelope
reserve input space conservatively for these small text-only fixtures. This
is not a tokenizer guarantee or a provider-enforced billing cap. Caller-supplied
prices can be stale, and provider accounting can differ. Any observed overrun
halts the run. Every attempted request retains its full local reservation.

Primary references, checked 2026-11-23:
https://developers.openai.com/api/reference/resources/responses/methods/create
https://developers.openai.com/api/docs/guides/token-counting
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import uuid
from decimal import Decimal, InvalidOperation
from typing import Any, Callable


SCHEMA = "wolftrap.neuralscope.api-lab/v1"
API_HOST = "api.openai.com"
API_PATH = "/v1/responses"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
INPUT_ENVELOPE_TOKENS = 1024
MAX_PILOT_USD = Decimal("5")
_SECRET = re.compile(r"sk-[A-Za-z0-9_-]{8,}")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
_ALLOWED_CONFIG = {
    "model", "input_usd_per_million", "output_usd_per_million",
    "budget_usd", "max_output_tokens", "max_requests", "max_total_tokens",
    "max_input_tokens_per_request", "timeout_s", "tariff_verified",
    "price_source", "expected_response_model", "reasoning_effort", "cases", "description",
}


class PlanError(ValueError):
    """A fixed, non-sensitive reason why an experiment cannot run."""


class TransportError(RuntimeError):
    """Transport failure; never includes server bodies or credentials."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _money(value: Decimal) -> str:
    return format(value, "f")


def _positive_decimal(value: Any, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise PlanError(name + "_REQUIRED")
    encoded = str(value)
    if len(encoded) > 64:
        raise PlanError(name + "_INVALID")
    try:
        result = Decimal(encoded)
    except InvalidOperation as exc:
        raise PlanError(name + "_INVALID") from exc
    if not result.is_finite() or result < Decimal("0.000000000001") or result > 1_000_000:
        raise PlanError(name + "_INVALID")
    return result


def _integer(value: Any, low: int, high: int, name: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise PlanError(name + "_INVALID")
    return value


def _clean(value: Any, secret: str | None = None) -> Any:
    """Redact key-shaped strings and the live key from every recorded string."""
    if isinstance(value, str):
        if secret:
            value = value.replace(secret, "[REDACTED]")
        return _SECRET.sub("[REDACTED]", value)
    if isinstance(value, list):
        return [_clean(item, secret) for item in value]
    if isinstance(value, dict):
        return {_clean(str(key), secret): _clean(item, secret)
                for key, item in value.items()}
    return value


def _strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("NONFINITE_JSON")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _validated(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict) or set(config) - _ALLOWED_CONFIG:
        raise PlanError("UNKNOWN_CONFIG_FIELD_OR_INVALID_CONFIG")
    model = config.get("model")
    if not isinstance(model, str) or not _ID.fullmatch(model) or model == "SELECT_MODEL":
        raise PlanError("EXPLICIT_MODEL_ID_REQUIRED")
    pin = config.get("expected_response_model")
    if pin is not None and (not isinstance(pin, str) or not _ID.fullmatch(pin)):
        raise PlanError("RESPONSE_MODEL_PIN_INVALID")
    effort = config.get("reasoning_effort")
    if effort is not None and (not isinstance(effort, str) or effort not in {
            "none", "low", "medium", "high", "xhigh", "max"}):
        raise PlanError("REASONING_EFFORT_INVALID")
    iprice = _positive_decimal(config.get("input_usd_per_million"), "INPUT_TARIFF")
    oprice = _positive_decimal(config.get("output_usd_per_million"), "OUTPUT_TARIFF")
    budget = _positive_decimal(config.get("budget_usd", "5"), "BUDGET")
    if budget > MAX_PILOT_USD:
        raise PlanError("PILOT_BUDGET_ABOVE_5_USD")
    max_output = _integer(config.get("max_output_tokens", 256), 16, 4096, "MAX_OUTPUT")
    max_requests = _integer(config.get("max_requests", 8), 1, 100, "MAX_REQUESTS")
    max_total = _integer(config.get("max_total_tokens", 32000), 16, 1_000_000, "MAX_TOTAL_TOKENS")
    max_input = _integer(config.get("max_input_tokens_per_request", 8192), 1024, 65536, "MAX_INPUT_TOKENS")
    timeout = _integer(config.get("timeout_s", 60), 1, 120, "TIMEOUT")
    if type(config.get("tariff_verified", False)) is not bool:
        raise PlanError("TARIFF_VERIFIED_MUST_BE_BOOLEAN")
    price_source = config.get("price_source")
    if price_source is not None and (not isinstance(price_source, str) or len(price_source) > 2048):
        raise PlanError("PRICE_SOURCE_INVALID")
    cases = config.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= max_requests:
        raise PlanError("CASE_COUNT_EXCEEDS_REQUEST_CAP_OR_IS_EMPTY")
    ids = set()
    normalized = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "instructions", "input", "expected"}:
            raise PlanError("CASE_FIELDS_INVALID")
        cid = case["id"]
        if not isinstance(cid, str) or not _ID.fullmatch(cid) or cid in ids:
            raise PlanError("CASE_ID_INVALID_OR_DUPLICATE")
        ids.add(cid)
        for field in ("instructions", "input"):
            if not isinstance(case[field], str) or not 1 <= len(case[field].encode("utf-8")) <= 32768:
                raise PlanError("CASE_TEXT_INVALID_OR_TOO_LARGE")
        expected = case["expected"]
        if not isinstance(expected, dict) or set(expected) != {"equals_json"}:
            raise PlanError("EXACT_JSON_EXPECTATION_REQUIRED")
        try:
            expected_bytes = _canonical(expected["equals_json"])
        except (ValueError, TypeError, RecursionError) as exc:
            raise PlanError("EXPECTED_VALUE_NOT_FINITE_JSON") from exc
        if len(expected_bytes) > 4096:
            raise PlanError("EXPECTED_VALUE_TOO_LARGE")
        input_reserve = (len(case["instructions"].encode("utf-8"))
                         + len(case["input"].encode("utf-8")) + INPUT_ENVELOPE_TOKENS)
        if input_reserve > max_input:
            raise PlanError("INPUT_RESERVATION_EXCEEDS_PER_REQUEST_CAP")
        reservation = (Decimal(input_reserve) * iprice + Decimal(max_output) * oprice) / 1_000_000
        normalized.append({"case": case, "input_reserve": input_reserve,
                           "reservation": reservation})
    total_reserve = sum((item["reservation"] for item in normalized), Decimal(0))
    total_tokens = sum(item["input_reserve"] + max_output for item in normalized)
    if total_tokens > max_total:
        raise PlanError("TOTAL_TOKEN_RESERVATION_EXCEEDS_CAP")
    if total_reserve > budget:
        raise PlanError("TOTAL_COST_RESERVATION_EXCEEDS_BUDGET")
    return {"model": model, "pin": pin, "reasoning_effort": effort,
            "iprice": iprice, "oprice": oprice,
            "budget": budget, "max_output": max_output, "timeout": timeout,
            "cases": normalized, "total_reserve": total_reserve,
            "total_tokens": total_tokens,
            "price_source": price_source,
            "tariff_verified": config.get("tariff_verified", False)}


def _plan_from_valid(valid: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "mode": "DRY_RUN", "ready": True,
        "network_calls": 0, "api_key_read": False,
        "model_requested": valid["model"],
        "expected_response_model": valid["pin"],
        "reasoning_effort": valid["reasoning_effort"],
        "tariff_verified_by_operator": valid["tariff_verified"],
        "input_usd_per_million": _money(valid["iprice"]),
        "output_usd_per_million": _money(valid["oprice"]),
        "price_source": valid["price_source"],
        "live_ready": valid["tariff_verified"],
        "budget_usd": _money(valid["budget"]),
        "reserved_cost_estimate_usd": _money(valid["total_reserve"]),
        "reserved_total_tokens": valid["total_tokens"],
        "billing_guarantee": "NONE_LOCAL_ESTIMATE_ONLY",
        "input_reservation_method": "UTF8_BYTES_PLUS_1024_TOKEN_ENVELOPE_NOT_TOKENIZER_GUARANTEE",
        "scope": "SYNTHETIC_BEHAVIOR_ONLY_NO_WEIGHT_ACCESS_NO_TOOLS_EXECUTED",
        "requests": [{
            "id": item["case"]["id"],
            "prompt_sha256": _sha({key: item["case"][key] for key in ("instructions", "input")}),
            "expected_sha256": _sha(item["case"]["expected"]["equals_json"]),
            "input_token_reservation": item["input_reserve"],
            "max_output_tokens": valid["max_output"],
            "reserved_cost_estimate_usd": _money(item["reservation"]),
        } for item in valid["cases"]],
        "notes": [
            "No tokenizer or provider billing guarantee is implied by the input reservation.",
            "Supplied prices are a planning envelope for the requested model's standard text tier, including any applicable cache-write pricing; reconcile final charges with provider billing.",
            "store:false disables later API retrieval; it does not establish zero provider retention.",
            "Fixtures use exact JSON assertions. Refusals, malformed or incomplete answers are inconclusive.",
        ],
    }


def plan(config: dict[str, Any]) -> dict[str, Any]:
    """Validate a small experiment and estimate reservations without networking."""
    try:
        return _clean(_plan_from_valid(_validated(config)))
    except PlanError as exc:
        return {"schema": SCHEMA, "mode": "DRY_RUN", "ready": False,
                "network_calls": 0, "api_key_read": False, "requests": [],
                "reason": str(exc), "billing_guarantee": "NONE_LOCAL_ESTIMATE_ONLY"}


def _http_transport(payload: dict[str, Any], *, timeout_s: int,
                    key: str) -> dict[str, Any]:
    """One HTTPS POST; no redirects, proxies, tools, uploads, or retries."""
    encoded = _canonical(payload)
    connection = http.client.HTTPSConnection(API_HOST, timeout=timeout_s,
                                           context=ssl.create_default_context())
    try:
        connection.request("POST", API_PATH, body=encoded, headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "Content-Length": str(len(encoded)),
            "User-Agent": "WolfTrap-NeuralScope/0.1-experimental",
            "X-Client-Request-Id": str(uuid.uuid4()),
        })
        response = connection.getresponse()
        request_id = response.getheader("x-request-id")
        if not isinstance(request_id, str) or not _ID.fullmatch(request_id):
            request_id = None
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TransportError("RESPONSE_SIZE_LIMIT")
        if response.status != 200:
            return {"status_code": response.status, "request_id": request_id,
                    "body": None}
        try:
            body = _strict_json(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise TransportError("INVALID_RESPONSE_JSON") from exc
        return {"status_code": response.status, "request_id": request_id,
                "body": body}
    finally:
        connection.close()


def _usage(body: dict[str, Any]) -> dict[str, int]:
    usage = body.get("usage")
    if not isinstance(usage, dict):
        raise PlanError("MISSING_USAGE")
    result = {}
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        value = usage.get(field)
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            raise PlanError("INVALID_USAGE")
        result[field] = value
    if result["total_tokens"] != result["input_tokens"] + result["output_tokens"]:
        raise PlanError("INCONSISTENT_USAGE")
    for container, field, bound in (("output_tokens_details", "reasoning_tokens", "output_tokens"),
                                    ("input_tokens_details", "cached_tokens", "input_tokens"),
                                    ("input_tokens_details", "cache_write_tokens", "input_tokens")):
        details = usage.get(container)
        if details is not None:
            if not isinstance(details, dict):
                raise PlanError("INVALID_USAGE_DETAILS")
            if field in details:
                value = details[field]
                if type(value) is not int or not 0 <= value <= result[bound]:
                    raise PlanError("INCONSISTENT_USAGE_DETAILS")
                result[field] = value
    return result


def _evaluate(body: dict[str, Any], expected: Any) -> dict[str, Any]:
    if body.get("status") != "completed" or body.get("error") is not None or body.get("incomplete_details") is not None:
        return {"outcome": "INCONCLUSIVE", "reason": "RESPONSE_NOT_COMPLETE", "halt": True}
    output = body.get("output")
    if not isinstance(output, list) or not output:
        return {"outcome": "INCONCLUSIVE", "reason": "NO_OUTPUT", "halt": True}
    texts = []
    for item in output:
        if not isinstance(item, dict):
            return {"outcome": "INCONCLUSIVE", "reason": "INVALID_OUTPUT_ITEM", "halt": True}
        if item.get("type") == "reasoning":
            continue  # Do not record or mistake reasoning summaries for an answer.
        if item.get("type") != "message" or item.get("role") != "assistant" or item.get("status") != "completed":
            return {"outcome": "INCONCLUSIVE", "reason": "UNEXPECTED_OUTPUT_ITEM", "halt": True}
        content = item.get("content")
        if not isinstance(content, list):
            return {"outcome": "INCONCLUSIVE", "reason": "INVALID_MESSAGE_CONTENT", "halt": True}
        for part in content:
            if not isinstance(part, dict):
                return {"outcome": "INCONCLUSIVE", "reason": "INVALID_CONTENT_PART", "halt": True}
            if part.get("type") == "refusal":
                return {"outcome": "INCONCLUSIVE", "reason": "MODEL_REFUSAL", "halt": False}
            if part.get("type") != "output_text" or not isinstance(part.get("text"), str):
                return {"outcome": "INCONCLUSIVE", "reason": "UNEXPECTED_CONTENT_PART", "halt": True}
            texts.append(part["text"])
    text = "".join(texts)
    record = {"output_text": text, "output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    try:
        actual = _strict_json(text)
    except (ValueError, RecursionError):
        return {**record, "outcome": "INCONCLUSIVE", "reason": "NOT_EXACT_JSON", "halt": False}
    # Canonical bytes distinguish JSON booleans from numbers (True != 1 here).
    equal = _canonical(actual) == _canonical(expected)
    return {**record, "outcome": "MATCH" if equal else "MISMATCH",
            "reason": "EXACT_JSON_MATCH" if equal else "EXACT_JSON_MISMATCH", "halt": False}


def run(config: dict[str, Any], *, live: bool = False,
        transport: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run only after explicit ``live=True``; an injected transport is marked MOCK.

    Mock transports receive ``transport(payload, timeout_s=...)`` and return
    ``{status_code: int, request_id: str|None, body: dict|None}``. They are not
    called by a dry run. Real HTTPS reads OPENAI_API_KEY only after validation.
    """
    report = plan(config)
    if live is not True or not report["ready"]:
        return {**report, "verdict": "NOT_RUN", "records": [],
                "estimated_usage_cost_usd": "0", "reservation_consumed_usd": "0"}
    valid = _validated(config)
    is_mock = transport is not None
    if not is_mock and not valid["tariff_verified"]:
        return {**report, "verdict": "NOT_RUN", "reason": "CONFIRMED_TARIFF_REQUIRED",
                "records": [], "estimated_usage_cost_usd": "0", "reservation_consumed_usd": "0"}
    secret = None
    if not is_mock:
        secret = os.environ.get("OPENAI_API_KEY")
        if not secret or len(secret) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in secret):
            return {**report, "api_key_read": True, "verdict": "NOT_RUN",
                    "reason": "API_KEY_MISSING_OR_INVALID", "records": [],
                    "estimated_usage_cost_usd": "0", "reservation_consumed_usd": "0"}
    report.update({"mode": "MOCK" if is_mock else "LIVE", "records": [],
                   "api_key_read": not is_mock, "halted": False,
                   "provider_billed_amount_usd": None,
                   "price_basis": "SUPPLIED_TEXT_TARIFF_PLANNING_ENVELOPE"})
    consumed = Decimal(0)
    measured = Decimal(0)
    for request, planned in zip(valid["cases"], report["requests"], strict=True):
        case = request["case"]
        if consumed + request["reservation"] > valid["budget"]:
            report.update({"halted": True, "halt_reason": "BUDGET_RESERVATION_EXHAUSTED"})
            break
        payload = {"model": valid["model"], "instructions": case["instructions"],
                   "input": case["input"], "max_output_tokens": valid["max_output"],
                   "store": False, "tools": [], "tool_choice": "none",
                   "service_tier": "default", "stream": False,
                   "truncation": "disabled"}
        if valid["reasoning_effort"] is not None:
            payload["reasoning"] = {"effort": valid["reasoning_effort"]}
        record = {**planned, "request_sha256": _sha(payload), "attempt": 1,
                  "outcome": "INCONCLUSIVE", "usage": None}
        consumed += request["reservation"]
        report["network_calls"] += 0 if is_mock else 1
        record["transport_attempted"] = True
        try:
            result = (transport(payload, timeout_s=valid["timeout"]) if is_mock
                      else _http_transport(payload, timeout_s=valid["timeout"], key=secret))
            if not isinstance(result, dict):
                raise PlanError("INVALID_TRANSPORT_RESULT")
            request_id = result.get("request_id")
            record["request_id"] = request_id if isinstance(request_id, str) and _ID.fullmatch(request_id) else None
            code = result.get("status_code")
            if type(code) is not int or not 100 <= code <= 599:
                raise PlanError("INVALID_HTTP_STATUS")
            record["http_status"] = code
            if code != 200:
                raise PlanError("HTTP_STATUS_" + str(code))
            body = result.get("body")
            if not isinstance(body, dict):
                raise PlanError("INVALID_RESPONSE_BODY")
            model = body.get("model")
            if not isinstance(model, str) or not _ID.fullmatch(model):
                raise PlanError("RESPONSE_MODEL_MISSING_OR_INVALID")
            record["model_returned"] = model
            response_id = body.get("id")
            record["response_id"] = response_id if isinstance(response_id, str) and _ID.fullmatch(response_id) else None
            usage = _usage(body)
            record["usage"] = usage
            cost = (Decimal(usage["input_tokens"]) * valid["iprice"]
                    + Decimal(usage["output_tokens"]) * valid["oprice"]) / 1_000_000
            measured += cost
            record["estimated_usage_cost_usd"] = _money(cost)
            if cost > request["reservation"]:
                consumed += cost - request["reservation"]
            if usage["input_tokens"] > request["input_reserve"] or usage["output_tokens"] > valid["max_output"]:
                raise PlanError("TOKEN_RESERVATION_EXCEEDED")
            if valid["pin"] is not None and model != valid["pin"]:
                raise PlanError("RESPONSE_MODEL_PIN_MISMATCH")
            if body.get("service_tier") not in (None, "default"):
                raise PlanError("UNEXPECTED_SERVICE_TIER")
            evaluated = _evaluate(body, case["expected"]["equals_json"])
            should_halt = evaluated.pop("halt")
            record.update(evaluated)
            if should_halt:
                report.update({"halted": True, "halt_reason": record["reason"]})
        except PlanError as exc:
            record.update({"outcome": "INCONCLUSIVE", "reason": str(exc)})
            report.update({"halted": True, "halt_reason": str(exc)})
        except Exception:
            # Messages, bodies, stack traces, and auth headers are deliberately absent.
            record.update({"outcome": "INCONCLUSIVE", "reason": "AMBIGUOUS_TRANSPORT_FAILURE_NO_RETRY"})
            report.update({"halted": True, "halt_reason": record["reason"]})
        report["records"].append(record)
        if report["halted"]:
            break
    report["estimated_usage_cost_usd"] = _money(measured)
    report["reservation_consumed_usd"] = _money(consumed)
    report["mock_transport_calls"] = len(report["records"]) if is_mock else 0
    report["unexecuted_cases"] = len(valid["cases"]) - len(report["records"])
    outcomes = [row["outcome"] for row in report["records"]]
    if report["halted"] or "INCONCLUSIVE" in outcomes or report["unexecuted_cases"]:
        report["verdict"] = "INCONCLUSIVE"
    elif "MISMATCH" in outcomes:
        report["verdict"] = "FIXTURE_MISMATCH"
    else:
        report["verdict"] = "FIXTURE_MATCH"
    if is_mock:
        report["verdict"] = "MOCK_" + report["verdict"]
    return _clean(report, secret)
