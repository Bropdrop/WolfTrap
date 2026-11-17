"""Bounded defensive correlations over fictional identity-audit summaries."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any


SCHEMA = "wolftrap.synthetic-identity-telemetry/v1"
LIMITS = {
    "input_bytes": 64 * 1024,
    "events": 256,
    "tick": 1_000_000,
    "alias": 10_000,
    "auth_window_minutes": 15,
    "auth_count": 100_000,
    "minimum_baseline_windows": 12,
    "maximum_baseline_windows": 96,
    "minimum_auth_count": 20,
    "auth_volume_ratio": 3,
    "privileged_chain_ticks": 5,
}
RULES = {
    "WT-IDENTITY-001": "Successful app-only sign-in from a new source class",
    "WT-IDENTITY-002": "Successful app-only sign-in outside an expected tenant relationship",
    "WT-IDENTITY-003": "Application credential addition outside an approved change window",
    "WT-IDENTITY-004": "Elevated consent or role assignment outside an approved change window",
    "WT-IDENTITY-005": "App-only authentication volume above the authored baseline threshold",
    "WT-IDENTITY-006": "Credential addition, privilege change and protected operation in one context",
}
INCOMPLETE_REASONS = frozenset({
    "UNSUPPORTED_INPUT", "SOURCE_CLASS_UNKNOWN", "TENANT_RELATIONSHIP_UNKNOWN",
    "INSUFFICIENT_AUTH_BASELINE", "CHANGE_CONTEXT_UNKNOWN",
})
COMMON_FIELDS = {"tick", "tenant", "app", "kind"}
WRITE_FIELDS = {
    "credential_added": {"change_context"},
    "consent_granted": {"change_context", "privilege"},
    "role_assigned": {"change_context", "privilege"},
    "protected_operation": {"change_context"},
}
EXTRA_FIELDS = {
    **WRITE_FIELDS,
    "sign_in": {"mode", "outcome", "source_class", "credential_tenant", "tenant_relationship"},
    "auth_volume": {"mode", "attempts", "usual_attempts", "baseline_windows"},
}
GOVERNANCE_KINDS = {"consent_granted", "role_assigned"}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate object field")
        values[key] = value
    return values


def _reject_constant(_value: str) -> None:
    raise ValueError("unsupported numeric value")


def _integer(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _validate_sign_in(event: dict[str, Any]) -> None:
    owner = event["credential_tenant"]
    relationship = event["tenant_relationship"]
    if (event["mode"] not in ("app_only", "delegated")
            or event["outcome"] not in ("success", "failure")
            or event["source_class"] not in ("known", "new", "unknown")
            or relationship not in ("same", "expected_partner", "unexpected", "unknown")):
        raise ValueError("unsupported sign-in metadata")
    if owner is None:
        if relationship != "unknown":
            raise ValueError("missing credential tenant cannot establish relationship")
    elif (event["mode"] != "app_only" or not _integer(owner, 1, LIMITS["alias"])
          or (relationship == "same") != (owner == event["tenant"])):
        raise ValueError("inconsistent credential tenant metadata")


def _validate_volume(event: dict[str, Any]) -> None:
    windows = event["baseline_windows"]
    usual = event["usual_attempts"]
    if (event["mode"] not in ("app_only", "delegated")
            or not _integer(event["attempts"], 0, LIMITS["auth_count"])
            or not _integer(windows, 0, LIMITS["maximum_baseline_windows"])
            or (windows == 0 and usual is not None)
            or (windows > 0 and not _integer(usual, 0, LIMITS["auth_count"]))):
        raise ValueError("invalid authentication volume summary")


def parse_identity_trace(raw: bytes) -> list[dict[str, Any]]:
    """Validate the synthetic schema, including cross-field and ordering rules."""
    if type(raw) is not bytes or not 1 <= len(raw) <= LIMITS["input_bytes"]:
        raise ValueError("unsupported input size or type")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object,
                          parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ValueError("invalid UTF-8 JSON input") from None
    if type(data) is not dict or set(data) != {"schema", "events"} or data["schema"] != SCHEMA:
        raise ValueError("unsupported input schema")
    events = data["events"]
    if type(events) is not list or not 1 <= len(events) <= LIMITS["events"]:
        raise ValueError("event count outside bounds")
    previous = 0
    for event in events:
        if type(event) is not dict or type(event.get("kind")) is not str:
            raise ValueError("unsupported audit event")
        kind = event["kind"]
        if kind not in EXTRA_FIELDS or set(event) != COMMON_FIELDS | EXTRA_FIELDS[kind]:
            raise ValueError("unsupported or missing audit event fields")
        if (not _integer(event["tick"], previous, LIMITS["tick"])
                or not _integer(event["tenant"], 1, LIMITS["alias"])
                or not _integer(event["app"], 1, LIMITS["alias"])):
            raise ValueError("invalid or unordered tick or local alias")
        previous = event["tick"]
        if kind == "sign_in":
            _validate_sign_in(event)
        elif kind == "auth_volume":
            _validate_volume(event)
        elif event["change_context"] not in ("approved_window", "unplanned", "unknown"):
            raise ValueError("unsupported change context")
        elif kind in GOVERNANCE_KINDS and event["privilege"] not in ("limited", "elevated"):
            raise ValueError("unsupported privilege category")
    return events


def inspect_identity_trace(raw: bytes) -> dict[str, Any]:
    """Return conditional findings and coverage gaps without echoing input values."""
    try:
        events = parse_identity_trace(raw)
    except ValueError:
        return {
            "status": "INCONCLUSIVE", "findings": [],
            "inconclusive": [{"event_index": None, "reason": "UNSUPPORTED_INPUT"}],
        }

    findings: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    credentials: dict[tuple[int, int], list[int]] = defaultdict(list)
    governance: dict[tuple[int, int], list[int]] = defaultdict(list)

    def match(number: int, *positions: int) -> None:
        findings.append({"rule_id": f"WT-IDENTITY-{number:03d}", "event_indices": list(positions)})

    def unknown(position: int, reason: str) -> None:
        incomplete.append({"event_index": position, "reason": reason})

    for position, event in enumerate(events):
        kind = event["kind"]
        if kind == "sign_in":
            if event["mode"] != "app_only" or event["outcome"] != "success":
                continue
            if event["source_class"] == "new":
                match(1, position)
            elif event["source_class"] == "unknown":
                unknown(position, "SOURCE_CLASS_UNKNOWN")
            if event["tenant_relationship"] == "unexpected":
                match(2, position)
            elif event["tenant_relationship"] == "unknown":
                unknown(position, "TENANT_RELATIONSHIP_UNKNOWN")
            continue

        if kind == "auth_volume":
            if event["mode"] != "app_only":
                continue
            if event["baseline_windows"] < LIMITS["minimum_baseline_windows"]:
                unknown(position, "INSUFFICIENT_AUTH_BASELINE")
            elif (event["attempts"] >= LIMITS["minimum_auth_count"]
                  and event["attempts"] >= LIMITS["auth_volume_ratio"] * max(1, event["usual_attempts"])):
                match(5, position)
            continue

        if event["change_context"] == "unknown":
            unknown(position, "CHANGE_CONTEXT_UNKNOWN")
        if event["change_context"] != "unplanned":
            continue
        subject = (event["tenant"], event["app"])
        if kind == "credential_added":
            match(3, position)
            credentials[subject].append(position)
        elif kind in GOVERNANCE_KINDS and event["privilege"] == "elevated":
            match(4, position)
            governance[subject].append(position)
        elif kind == "protected_operation":
            # Choose the latest strictly earlier qualifying privilege change and
            # credential addition. Equal-tick order does not establish causality.
            oldest = event["tick"] - LIMITS["privileged_chain_ticks"]
            privilege = next((i for i in reversed(governance.get(subject, ()))
                              if oldest <= events[i]["tick"] < event["tick"]), None)
            if privilege is not None:
                credential = next((i for i in reversed(credentials.get(subject, ()))
                                   if oldest <= events[i]["tick"] < events[privilege]["tick"]), None)
                if credential is not None:
                    match(6, credential, privilege, position)

    status = "INCONCLUSIVE" if incomplete else ("REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH")
    return {"status": status, "findings": findings, "inconclusive": incomplete}
